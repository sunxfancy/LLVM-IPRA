
#include "llvm/Analysis/BlockFrequencyInfo.h"
#include "llvm/Support/Alignment.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/LazyBlockFrequencyInfo.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/CodeGen/LazyMachineBlockFrequencyInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/RegisterUsageInfo.h"
#include "llvm/CodeGen/TargetFrameLowering.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "fdo-ipra"

static cl::opt<bool> OnHotEntryAndHotCallGraph("fdoipra-both-hot",
                                               cl::init(true), cl::Hidden);
static cl::opt<bool> ColdCallsiteColdCallee("fdoipra-cc", cl::init(true),
                                            cl::Hidden);
static cl::opt<bool> ColdCallsiteHotCallee("fdoipra-ch", cl::init(false),
                                           cl::Hidden);
static cl::opt<bool> HotCallsiteColdCallee("fdoipra-hc", cl::init(false),
                                           cl::Hidden);
static cl::opt<bool> HotCallsiteHotCallee("fdoipra-hh", cl::init(false),
                                          cl::Hidden);

static cl::opt<bool> UseCalleeReg("fdoipra-use-callee-reg", cl::init(true),
                                  cl::Hidden);

static cl::opt<bool> UseCallerReg("fdoipra-use-caller-reg", cl::init(false),
                                  cl::Hidden);

static cl::opt<std::string> RegProfilePath("fdoipra-profile", cl::init(""),
                                           cl::Hidden);

static cl::opt<bool> FDOIPRARunOnMachineFunction("fdoipra-on-machinefunc",
                                                 cl::init(false), cl::Hidden);

static cl::opt<std::string> UseMapOutput("use_bbidx_map", cl::init(""),
                                         cl::Hidden);

static cl::opt<std::string> AdditionHotFunctionList("fdoipra-hot-list",
                                          cl::init(""), cl::Hidden);

static cl::opt<std::string> OutputPSI("fdoipra-psi", cl::ValueOptional,
                                      cl::init("off"), cl::Hidden);

static cl::opt<float> CallsiteColdRatio("fdoipra-ccr",
                                      cl::init(10.0f), cl::Hidden);


namespace llvm {
  cl::opt<std::string> MapOutput("bbidx_map", cl::init(""), cl::Hidden);
}

namespace {

struct RegProfile {
  struct Function {
    int hot_on_entry;
    std::set<int> hot_bb_idx;
  };

  std::map<std::string, Function> hot_functions;

  void load(std::string path) {
    std::ifstream input(path);
    std::string line1, line2;
    while (std::getline(input, line1)) {
      std::getline(input, line2);

      std::istringstream iss(line1);
      std::string function;
      int hot_on_entry;
      int size;
      iss >> function >> hot_on_entry >> size;

      std::istringstream iss2(line2);
      std::set<int> hot_bb_idx;
      for (int i = 0; i < size; ++i) {
        int bb_idx;
        iss2 >> bb_idx;
        hot_bb_idx.insert(bb_idx);
      }
      hot_functions[function] = Function{hot_on_entry, hot_bb_idx};
    }
  }

  static RegProfile &getProfile() {
    static RegProfile profile;
    if (!RegProfilePath.empty())
      profile.load(RegProfilePath);
    return profile;
  }
};


/**
 * This class is used to query the frequence of a function or a callsite
 */
class FDOQuery {
 public:
  FDOQuery(llvm::Pass* pass) : pass(pass) {}

  bool isFunctionEntryCold(const Function *f) {
    if (use_hot_function_list &&
        hot_functions.count(f->getName().str())) return false;
    if (use_PSI) {
      return PSI->isFunctionEntryCold(f);
    } else {
      auto it = RP->hot_functions.find(f->getName().str());
      return it == RP->hot_functions.end() || it->second.hot_on_entry == 0;
    }
  }

  bool isFunctionEntryHot(const Function *f) {
    if (use_hot_function_list &&
        hot_functions.count(f->getName().str())) return true;
    if (use_PSI) {
      return PSI->isFunctionEntryHot(f);
    } else {
      auto it = RP->hot_functions.find(f->getName().str());
      return it != RP->hot_functions.end() && it->second.hot_on_entry != 0;
    }
  }

  bool isColdCallSite(const CallBase &b) {
    if (use_PSI) {
      if (PSI->isColdCallSite(b, BFI)) {
        auto callsite = BFI->getBlockProfileCount(b.getParent());
        auto entry = BFI->getBlockProfileCount(
                              &b.getFunction()->getEntryBlock());
        if (callsite.hasValue() && entry.hasValue()) {
          return entry.getValue() > callsite.getValue() * CallsiteColdRatio;
        }
      }
      return false;
      // This method is not suitable here
      // return PSI->isColdCallSite(b, BFI);
    } else {
      // TODO: map machine basic block back to here
      return false;
    }
  }

  bool isFunctionHotInCallGraph(const Function* f) {
    if (use_hot_function_list &&
        hot_functions.count(f->getName().str())) return true;
    if (use_PSI) {
      return PSI->isFunctionHotInCallGraph(f, *BFI);
    } else {
      return RP->hot_functions.find(f->getName().str()) !=
             RP->hot_functions.end();
    }
  }

  bool initProfile() {
    if (!RegProfilePath.empty()) {
      has_profile = true;
      RP = &RegProfile::getProfile();
      use_PSI = false;
    } else {
      PSI = &pass->getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
      if (PSI && PSI->hasProfileSummary()) {
        use_PSI = true;
        has_profile = true;
      }
    }
    if (!AdditionHotFunctionList.empty()) {
      std::fstream fin(AdditionHotFunctionList, std::ios_base::in);
      std::string name;
      while (std::getline(fin, name)) hot_functions.insert(name);
      use_hot_function_list = true;
    }
    return has_profile;
  }

  void initBlockFreqInfo(Function *F) {
    if (use_PSI) {
      BFI = &pass->getAnalysis<BlockFrequencyInfoWrapperPass>(*F).getBFI();
    } else {
      auto it = RP->hot_functions.find(F->getName().str());
      if (it != RP->hot_functions.end()) {
        hot_bb = &it->second.hot_bb_idx;
        hot_on_entry = it->second.hot_on_entry;
      }
    }
  }

 protected:
  bool has_profile = false;
  bool use_PSI = true;

  llvm::Pass* pass;

  ProfileSummaryInfo *PSI = nullptr;
  BlockFrequencyInfo *BFI = nullptr;
  RegProfile *RP = nullptr;
  bool hot_on_entry = false;
  std::set<int> *hot_bb = nullptr;

  bool use_hot_function_list = false;
  std::set<std::string> hot_functions;
};


}    // namespace


namespace llvm {

/**
 * This pass is used to map the bb_index to the original basic block
 */
class MapBBIndex : public MachineFunctionPass {
 public:
  MapBBIndex() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "Map BBIndex to BasicBlock Index";
  }

  bool doInitialization(Module& M) override {
    LLVM_DEBUG(errs() << "Map Output: " << MapOutput);
    out.open(MapOutput, std::ios_base::out | std::ios_base::app);
    return false;
  }

  bool doFinalization(Module& M) override {
    out.close();
    return false;
  }

  int getNumber(const BasicBlock* bb) {
    if (bb == nullptr) return -1;
    const Function* F = bb->getParent();
    unsigned i; auto b = F->begin();
    for (i = 0; b != F->end(); b++, i++) {
      if (b.getNodePtr() == bb) return i;
    }
    return -1;
  }

  bool runOnMachineFunction(MachineFunction &MF) override {
    if (MF.getName().empty()) return false;

    // basic block to machine basic block ids
    std::map<unsigned, unsigned> idx_map;

    for (auto& MBB : MF) {
      const auto* BB = MBB.getBasicBlock();
      int index = getNumber(BB);
      if (index != -1) {
        idx_map[index] = MBB.getNumber();
      }
    }

    // print to file
    out << MF.getName().str() << " " << idx_map.size() << std::endl;
    for (auto it : idx_map) {
      out << it.first << " " << it.second << std::endl;
    }
    idx_map.clear();
    return false;
  }

 protected:
  static char ID;
  std::fstream out;
};

char MapBBIndex::ID = 0;

MachineFunctionPass *createMapBBIndexPass() { return new MapBBIndex(); }



static Function *completeFunction(Function *F, CallInst *Call) {
  if (!F->isDeclaration())
    return F;
  BasicBlock *BB = BasicBlock::Create(F->getContext(), "", F);
  IRBuilder<> Builder(BB);

  int indirect_offset = Call->isIndirectCall() ? 1 : 0;
  SmallVector<Value *, 12> arguments;
  for (int i = 0; i < Call->getFunctionType()->getFunctionNumParams(); ++i) {
    arguments.push_back(F->getArg(i + indirect_offset));
  }

  auto *callee =
      Call->isIndirectCall() ? F->getArg(0) : Call->getCalledOperand();

  auto *call = Builder.CreateCall(Call->getFunctionType(), callee, arguments);
  if (F->getReturnType()->isVoidTy())
    Builder.CreateRetVoid();
  else
    Builder.CreateRet(call);
  return F;
}

static Function *createAndReplaceUsingProxyFunction(CallInst *Call, Module &M) {
  if (Call->isIndirectCall()) {
    auto *FT = Call->getFunctionType();
    auto v = FT->params().vec();
    v.insert(v.begin(), Call->getCalledOperand()->getType());

    auto *NFT = FunctionType::get(FT->getReturnType(), v, false);
    auto *NF = Function::Create(NFT, GlobalValue::LinkageTypes::InternalLinkage,
                                "", M);
    NF->addFnAttr(Attribute::AttrKind::NoInline);
    completeFunction(NF, Call);

    SmallVector<Value *, 12> args;
    args.push_back(Call->getCalledOperand());
    for (auto k = Call->arg_begin(); k != Call->arg_end(); ++k) {
      args.push_back(k->get());
    }

    llvm::ReplaceInstWithInst(Call, CallInst::Create(NFT, NF, args));
    return NF;
  } else {
    LLVM_DEBUG(dbgs() << "createAndReplaceUsingProxyFunction Failed: " << *Call
                      << "\n");
    return nullptr;
  }
}


static Function *createProxyFunction(CallInst *Call, Module &M) {
  Function *F = Call->getCalledFunction();
  if (F == nullptr) {
    LLVM_DEBUG(dbgs() << "createProxyFunction Failed: " << *Call << "\n");
    return nullptr;
  }
  std::string name = F->getName().str();
  std::string new_name = name + "$NCSRProxy";
  LLVM_DEBUG(dbgs() << "createProxyFunction: " << new_name << "\n");
  LLVM_DEBUG(dbgs() << "createProxyFunction: " << *F << "\n");
  auto NF =
      M.getOrInsertFunction(new_name, F->getFunctionType(), F->getAttributes());
  LLVM_DEBUG(dbgs() << *(NF.getFunctionType()) << "\n";);
  LLVM_DEBUG(dbgs() << *(NF.getCallee()) << "\n";);

  dyn_cast<Function>(NF.getCallee())->addFnAttr(Attribute::AttrKind::NoInline);
  dyn_cast<Function>(NF.getCallee())
      ->setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
  auto FF = completeFunction(dyn_cast<Function>(NF.getCallee()), Call);
  Call->setCalledFunction(FF);
  return FF;
}

// ---------------------------------------------


/**
 *  This implementation works on MachineFunctions 
 */
class FDOAttrModification : public FunctionPass, public FDOQuery {
 public:
  FDOAttrModification() : FunctionPass(ID), FDOQuery(this) {}

  StringRef getPassName() const override {
    return "FDO based Attributes Modification Pass";
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<ProfileSummaryInfoWrapperPass>();
    AU.setPreservesAll();
    FunctionPass::getAnalysisUsage(AU);
  }

  bool runOnFunction(Function &F) override;

  bool doInitialization(Module &M) override {
    initProfile();

    if (!UseMapOutput.empty()) {
      std::fstream input(UseMapOutput, std::ios_base::in);

      std::string name; int size;
      while (!input.eof()) {
        input >> name >> size;
        for (int i = 0; i < size; i++) {
          int p, q;
          input >> p >> q;
          data[p] = q;
        }
      }
    }
    return false;
  }

 protected:
  Function *get_callee(const MachineInstr &MI);
  std::map<int, int> data;
  static char ID;
};

char FDOAttrModification::ID = 0;


bool FDOAttrModification::runOnFunction(Function &F) {
  if (!has_profile) return false;
  initBlockFreqInfo(&F);

  if (ColdCallsiteColdCallee)
    if (isFunctionEntryCold(&F))
      if (F.hasFnAttribute("no_caller_saved_registers") == false)
        F.addFnAttr("no_caller_saved_registers");

  if (OnHotEntryAndHotCallGraph) {
    if (!isFunctionEntryHot(&F) && !isFunctionHotInCallGraph(&F)) return false;
  } else {
    if (!isFunctionEntryHot(&F)) return false;
  }

  SmallVector<CallInst *, 64> callsites;
  for (auto &BB : F)
    for (auto &MI : BB)
      if (MI.getOpcode() == Instruction::Call) {
        CallInst *call = dyn_cast<CallInst>(&MI);
        callsites.push_back(call);
      }

  for (auto* call : callsites) {
    if (ColdCallsiteHotCallee) {
      Function *callee = call->getCalledFunction();
      // if callsit is cold and callee is not indirect call and here we
      // create another proxy function call
      if (callee && isColdCallSite(*call) && isFunctionEntryHot(callee)) {
        Function *NF = createProxyFunction(call, *F.getParent());
        if (NF && NF->hasFnAttribute("no_caller_saved_registers") == false) {
          NF->addFnAttr("no_caller_saved_registers");
          LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
          continue;
        }
      }
    }

    if (HotCallsiteColdCallee) {
      if (call->isIndirectCall()) {
        LLVM_DEBUG(dbgs() << "indirect call detected!\n" << *call << "\n");
        LLVM_DEBUG(dbgs() << "isColdCallsite: "
                          << isColdCallSite(*call) << "\n");
      }
      if (call->isIndirectCall() && isColdCallSite(*call)) {
        Function *NF = createAndReplaceUsingProxyFunction(call, *F.getParent());
        if (NF && NF->hasFnAttribute("no_caller_saved_registers") == false) {
          NF->addFnAttr("no_caller_saved_registers");
          LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
          continue;
        }
      }
    }
  }
  return false;
}

Pass *createFDOAttrModificationPass() { return new FDOAttrModification(); }


// ---------------------------------------------


class FDOAttrModification2 : public ModulePass, public FDOQuery {
 public:
  FDOAttrModification2() : ModulePass(ID), FDOQuery(this) {}

  StringRef getPassName() const override {
    return "FDO based Attributes Modification Pass";
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    ModulePass::getAnalysisUsage(AU);
    AU.addRequired<ProfileSummaryInfoWrapperPass>();
    AU.addRequired<BlockFrequencyInfoWrapperPass>();
    AU.setPreservesAll();
  }

  void CalleeToCaller(llvm::Function &F);
  void CallerToCallee(llvm::Function &F);

  bool runOnModule(Module &M) override;

  void dumpPSI(Module &M);

 protected:
  static char ID;
};

char FDOAttrModification2::ID = 0;

static void findAllCallsite(llvm::Function &F, SmallVector<CallInst*, 64>& callsites) {
  for (auto &BB : F)
    for (auto &MI : BB)
      if (MI.getOpcode() == Instruction::Call) {
        CallInst *call = dyn_cast<CallInst>(&MI);
        callsites.push_back(call);
      }
}

void FDOAttrModification2::CalleeToCaller(llvm::Function &F) {
  // if this is a not hot function
  if (OnHotEntryAndHotCallGraph) {
    if (!isFunctionEntryHot(&F) && !isFunctionHotInCallGraph(&F)) return;
  } else {
    if (!isFunctionEntryHot(&F)) return;
  }

  LLVM_DEBUG(dbgs() << "caller has profile: " << F.getName() << "\n");
  LLVM_DEBUG(dbgs() << "hot threshod = " << PSI->getHotCountThreshold()
                    << "\n");
  LLVM_DEBUG(dbgs() << "func addr: " << (&F.getFunction())
                    << "  func count: "
                    << F.getFunction().getEntryCount()->getCount() << "\n");

  LLVM_DEBUG(dbgs() << "hot caller: " << F.getName() << "\n");

  SmallVector<CallInst*, 64> callsites;
  findAllCallsite(F, callsites);

  for (CallInst *call : callsites) {
    if (ColdCallsiteColdCallee) {
      Function *callee = call->getCalledFunction();
      if (callee && !callee->isDeclaration()) {
        // if callee is cold on entry
        if (isFunctionEntryCold(callee)) {
          LLVM_DEBUG(dbgs() << "Adding attributes from hot " << F.getName()
                            << " to cold " << callee->getName() << "\n");
          if (callee->hasFnAttribute("no_caller_saved_registers") == false) {
            callee->addFnAttr("no_caller_saved_registers");
            LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
          }
          return;
        }
      }
    }

    if (ColdCallsiteHotCallee) {
      Function *callee = call->getCalledFunction();
      // if callsit is cold and callee is not indirect call and here we
      // create another proxy function call
      if (callee && isColdCallSite(*call) && isFunctionEntryHot(callee)) {
        Function *NF = createProxyFunction(call, *F.getParent());
        if (NF && NF->hasFnAttribute("no_caller_saved_registers") == false) {
          NF->addFnAttr("no_caller_saved_registers");
          LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
          return;
        }
      }
    }

    if (HotCallsiteColdCallee) {
      if (call->isIndirectCall()) {
        LLVM_DEBUG(dbgs() << "indirect call detected!\n" << *call << "\n");
        LLVM_DEBUG(dbgs() << "isColdCallsite: "
                          << isColdCallSite(*call) << "\n");
      }
      if (call->isIndirectCall() && isColdCallSite(*call)) {
        Function *NF = createAndReplaceUsingProxyFunction(call, *F.getParent());
        if (NF && NF->hasFnAttribute("no_caller_saved_registers") == false) {
          NF->addFnAttr("no_caller_saved_registers");
          LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
          return;
        }
      }
    }
  }
}




void FDOAttrModification2::CallerToCallee(llvm::Function &F) {
  // if this is a not cold function
  if (OnHotEntryAndHotCallGraph) {
    if (isFunctionEntryHot(&F) || isFunctionHotInCallGraph(&F)) return;
  } else {
    if (isFunctionEntryHot(&F)) return;
  }

  SmallVector<CallInst*, 64> callsites;
  findAllCallsite(F, callsites);

  for (CallInst *call : callsites) {
    if (ColdCallsiteHotCallee) {
      Function *callee = call->getCalledFunction();
      if (callee && !callee->isDeclaration()) {
        // if callee is hot on entry
        if (isFunctionEntryHot(callee)) {
          ValueToValueMapTy VMap;
          Function* clone = CloneFunction(callee, VMap);
          if (clone) {
            LLVM_DEBUG(dbgs() << "Adding attributes from cold " << F.getName()
                              << " to hot " << clone->getName() << "\n");
            if (clone->hasFnAttribute("no_callee_saved_registers") == false) {
              clone->addFnAttr("no_callee_saved_registers");
              LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
            }
            call->setCalledFunction(clone);
            return;
          }
        }
      }
    }
  }
}

bool FDOAttrModification2::runOnModule(Module &M) {
  initProfile();

  if (!has_profile) return false;

  for (auto &F : M) {
    if (F.isDeclaration()) continue;
    initBlockFreqInfo(&F);

    if (UseCalleeReg) CalleeToCaller(F);
    if (UseCallerReg) CallerToCallee(F);
  }

  if (OutputPSI != "off") dumpPSI(M);
  return false;
}

struct Record {
  std::string name;
  uint64_t freq;
  bool no_caller_saved_registers = false;
  bool in_hot_list = false;

  bool operator<(const Record& other) const {
    if (freq < other.freq) return true;
    if (freq == other.freq) return name < other.name;
    return false;
  }
};

void FDOAttrModification2::dumpPSI(Module &M) {
  std::string path = OutputPSI.empty() ? std::string("/tmp/fdoipra-psi.txt")
                                       : OutputPSI;
  auto* PSI = &getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
  if (PSI) {
    std::vector<Record> hot;
    std::vector<Record> normal;
    std::vector<Record> cold;

    for (auto &F : M) {
      if (F.isDeclaration()) continue;
      auto* BFI = &getAnalysis<BlockFrequencyInfoWrapperPass>(F).getBFI();
      if (!BFI) continue;
      bool in_hot_list = hot_functions.count(F.getName().str()) != 0;
      auto bpc = BFI->getBlockProfileCount(&F.getEntryBlock());
      uint64_t count = 0;
      if (bpc.hasValue()) count = bpc.getValue();
      Record record{F.getName().str(), count,
          F.hasFnAttribute("no_caller_saved_registers"), in_hot_list};

      if (PSI->isFunctionEntryHot(&F))
        hot.push_back(record);
      else if (PSI->isFunctionEntryCold(&F))
        cold.push_back(record);
      else
        normal.push_back(record);
    }

    std::sort(hot.begin(), hot.end());
    std::sort(cold.begin(), cold.end());
    std::sort(normal.begin(), normal.end());

    std::vector<Record>* buffer[3] = {&hot, &cold, &normal};
    std::vector<std::string> names = {"hot", "cold", "normal"};
    std::ofstream fout(path, std::ios_base::out);
    for (int i = 0; i < 3; ++i) {
      fout << names[i] << " functions:" << std::endl;
      for (int j = 0; j < buffer[i]->size(); ++j) {
        Record& c = buffer[i]->at(j);
        fout << (c.no_caller_saved_registers? "* ": "") <<
          c.name << " " << c.freq << (c.in_hot_list ? " hl" : "") << std::endl;
      }
    }
  }
}


Pass *createFDOAttrModification2Pass() { return new FDOAttrModification2(); }

}   // namespace llvm
