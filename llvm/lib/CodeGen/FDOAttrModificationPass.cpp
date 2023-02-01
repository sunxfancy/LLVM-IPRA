
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
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/Verifier.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "fdo-ipra"

static cl::opt<bool> UseNewImpl("fdoipra-new-impl", cl::init(false), cl::Hidden);

static cl::opt<bool> OnHotEntryAndHotCallGraph("fdoipra-both-hot", cl::init(true), cl::Hidden);
static cl::opt<bool> ColdCallsiteColdCallee("fdoipra-cc", cl::init(true), cl::Hidden);
static cl::opt<bool> ColdCallsiteHotCallee("fdoipra-ch", cl::init(false), cl::Hidden);
static cl::opt<bool> HotCallsiteColdCallee("fdoipra-hc", cl::init(false), cl::Hidden);
static cl::opt<bool> HotCallsiteHotCallee("fdoipra-hh", cl::init(false), cl::Hidden);

static cl::opt<bool> UseCalleeReg("fdoipra-use-callee-reg", cl::init(true), cl::Hidden);
static cl::opt<bool> UseCallerReg("fdoipra-use-caller-reg", cl::init(false), cl::Hidden);

static cl::opt<std::string> RegProfilePath("fdoipra-profile", cl::init(""), cl::Hidden);
static cl::opt<bool> FDOIPRARunOnMachineFunction("fdoipra-on-machinefunc", cl::init(false), cl::Hidden);

static cl::opt<std::string> UseMapOutput("use_bbidx_map", cl::init(""), cl::Hidden);
static cl::opt<std::string> AdditionHotFunctionList("fdoipra-hot-list", cl::init(""), cl::Hidden);
static cl::opt<std::string> OutputPSI("fdoipra-psi", cl::ValueOptional, cl::init("off"), cl::Hidden);
static cl::opt<float> CallsiteColdRatio("fdoipra-ccr", cl::init(10.0f), cl::Hidden);

static cl::opt<bool> ChangeDWARF("fdoipra-dwarf", cl::init(false), cl::Hidden);

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

  // first check hot function list, then check PSI, 
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
    if (!has_profile && !RegProfilePath.empty()) {
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
    if (!use_hot_function_list && !AdditionHotFunctionList.empty()) {
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


struct BBMap {
  void initBBMap() {
    if (UseMapOutput.empty()) return;
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
  std::map<int, int> data;
};

static void changeDebugFunctionName(llvm::Function &F, std::string attr) {
  if (!F.hasMetadata("dbg")) {
    Module& M = *F.getParent();
    M.addModuleFlag(Module::Warning, "Debug Info Version", llvm::DEBUG_METADATA_VERSION);
    M.addModuleFlag(Module::Warning, "Dwarf Version", dwarf::DWARF_VERSION);
    
    DIBuilder DBuilder(M);
    DIFile *Unit = DBuilder.createFile("unknown", ".");
    DBuilder.createCompileUnit(dwarf::DW_LANG_C99, Unit, "FDOAttrModification Pass", true, "", 0);
    DISubprogram *SP = DBuilder.createFunction(
        Unit, F.getName(), "", Unit, 0, 
        DBuilder.createSubroutineType(DBuilder.getOrCreateTypeArray(None)), 
        0, DINode::FlagZero, DISubprogram::SPFlagDefinition);
    F.setSubprogram(SP);
    DBuilder.finalizeSubprogram(SP); 
    DBuilder.finalize();
  }

  auto* metadata = F.getMetadata("dbg");
  auto* node = dyn_cast<DISubprogram>(metadata);
  std::string old_name = node->getName().str();
  std::string name = old_name;
  if (old_name.at(old_name.size()-1) == ')') {
    int begin = old_name.find_first_of('(');
    int end = old_name.size() - 1;
    if (old_name.find(attr, begin) == std::string::npos)
      name = old_name.substr(0, old_name.size()-1) + "," + attr + ")";
  } else {
    name = old_name + "(" + attr + ")";
  }
  if (node) node->replaceOperandWith(2, MDString::get(F.getContext(), name));
}

static void markFunctionNoCalleeSaved(llvm::Function &F) {
  if (F.hasFnAttribute("no_callee_saved_registers") == false)
    F.addFnAttr("no_callee_saved_registers");
  // changeDebugFunctionName(F, "no_callee_saved");
}

static void markFunctionNoCallerSaved(llvm::Function &F) {
  if (F.hasFnAttribute("no_caller_saved_registers") == false)
    F.addFnAttr("no_caller_saved_registers");
  // changeDebugFunctionName(F, "no_caller_saved");
}


static void findAllCallsite(llvm::Function &F, SmallVector<CallInst*, 64>& callsites) {
  for (auto &BB : F)
    for (auto &MI : BB)
      if (MI.getOpcode() == Instruction::Call) {
        CallInst *call = dyn_cast<CallInst>(&MI);
        callsites.push_back(call);
      }
}


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

    auto *NFT = FunctionType::get(FT->getReturnType(), v, FT->isVarArg());
    auto *NF = Function::Create(NFT, GlobalValue::LinkageTypes::InternalLinkage, "", M);
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
    LLVM_DEBUG(dbgs() << "createAndReplaceUsingProxyFunction Failed: " << *Call << "\n");
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
 *  This implementation works both for ThinLTO and FullLTO
 */
class FDOAttrModification : public ModulePass, public FDOQuery {
 public:
  FDOAttrModification() : ModulePass(ID), FDOQuery(this) {}

  StringRef getPassName() const override {
    return "FDO based Attributes Modification Pass";
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    ModulePass::getAnalysisUsage(AU);
    AU.addRequired<ProfileSummaryInfoWrapperPass>();
    AU.addRequired<BlockFrequencyInfoWrapperPass>();
    AU.setPreservesAll();
  }

  bool runOnModule(Module &M) override;

 protected:
  static char ID;

  void CalleeToCaller(llvm::Function &F);
  void CallerToCallee(llvm::Function &F);
};

char FDOAttrModification::ID = 0;


void FDOAttrModification::CalleeToCaller(llvm::Function &F) {
  if (OnHotEntryAndHotCallGraph) {
    if (!isFunctionEntryHot(&F) && !isFunctionHotInCallGraph(&F)) return;
  } else {
    if (!isFunctionEntryHot(&F)) return;
  }
  
  if (ColdCallsiteColdCallee)
    if (isFunctionEntryCold(&F)) {
      LLVM_DEBUG(dbgs() << "ColdFunction: " << F.getName() << "\n");
      markFunctionNoCallerSaved(F);
    }
  SmallVector<CallInst *, 64> callsites;
  for (auto &BB : F)
    for (auto &MI : BB)
      if (MI.getOpcode() == Instruction::Call) {
        CallInst *call = dyn_cast<CallInst>(&MI);
        callsites.push_back(call);
      }

  for (auto* call : callsites) {
    Function *callee = call->getCalledFunction();
    LLVM_DEBUG(dbgs() << "callsite: " << *call << "\n");
    LLVM_DEBUG(dbgs() << "IsColdCallsite: " << isColdCallSite(*call) << "\n");
    if (callee) {
      LLVM_DEBUG(dbgs() << "isFunctionEntryCold: " << isFunctionEntryCold(callee) << "\n");
      LLVM_DEBUG(dbgs() << "isFunctionEntryHot: " << isFunctionEntryHot(callee) << "\n");
    }

    if (ColdCallsiteColdCallee) {
      if (isFunctionEntryCold(callee)) {
        markFunctionNoCallerSaved(*callee);
      }
    }

    if (ColdCallsiteHotCallee) {
      // if callsit is cold and callee is not indirect call and here we
      // create another proxy function call
      if (callee && isColdCallSite(*call) && isFunctionEntryHot(callee)) {
        Function *NF = createProxyFunction(call, *F.getParent());
        if (NF) {
          markFunctionNoCallerSaved(F);
          LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
          continue;
        }
      }
    }

    if (HotCallsiteColdCallee) {
      if (call->isIndirectCall()) LLVM_DEBUG(dbgs() << "This is an indirect call!\n");
      if (call->isIndirectCall() && isColdCallSite(*call)) {
        Function *NF = createAndReplaceUsingProxyFunction(call, *F.getParent());
        if (NF) {
          markFunctionNoCallerSaved(*NF);
          LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
          continue;
        }
      }
    }
  }
}

void FDOAttrModification::CallerToCallee(llvm::Function &F) {
    
}

bool FDOAttrModification::runOnModule(Module &M) {
  if (!initProfile()) return false;
  

  for (auto &F : M) {
    if (F.isDeclaration()) continue;
    initBlockFreqInfo(&F);

    if (UseCalleeReg) CalleeToCaller(F);
    if (UseCallerReg) CallerToCallee(F);
  }

  LLVM_DEBUG(M.dump());
  return false;
}


// ---------------------------------------------

// Old implementation for FullLTO only
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
  std::unordered_map<Function *, Function *> ClonedFuncs;
  Function* getCloned(Function* F);

  static char ID;
};

char FDOAttrModification2::ID = 0;


void FDOAttrModification2::CalleeToCaller(llvm::Function &F) {
  // if this is a not hot function
  if (OnHotEntryAndHotCallGraph) {
    if (!isFunctionEntryHot(&F) && !isFunctionHotInCallGraph(&F)) return;
  } else {
    if (!isFunctionEntryHot(&F)) return;
  }

  LLVM_DEBUG(dbgs() << "caller has profile: " << F.getName() << "\n");
  LLVM_DEBUG(dbgs() << "hot threshod = " << PSI->getHotCountThreshold() << "\n");
  LLVM_DEBUG(dbgs() << "func addr: " << (&F.getFunction()) << "  func count: "
                    << F.getFunction().getEntryCount()->getCount() << "\n");
  LLVM_DEBUG(dbgs() << "hot caller: " << F.getName() << "\n");

  SmallVector<CallInst*, 64> callsites;
  findAllCallsite(F, callsites);

  for (CallInst *call : callsites) {
    Function *callee = call->getCalledFunction();
    LLVM_DEBUG(dbgs() << "callsite: " << *call << "\n");
    LLVM_DEBUG(dbgs() << "IsColdCallsite: " << isColdCallSite(*call) << "\n");
    if (callee && !callee->isDeclaration()) {
      LLVM_DEBUG(dbgs() << "isFunctionEntryCold: " << isFunctionEntryCold(callee) << "\n");
      LLVM_DEBUG(dbgs() << "isFunctionEntryHot: " << isFunctionEntryHot(callee) << "\n");
    }
    if (ColdCallsiteColdCallee) {
      if (callee && !callee->isDeclaration()) {
        // if callee is cold on entry
        if (isFunctionEntryCold(callee)) {
          LLVM_DEBUG(dbgs() << "Adding attributes from hot " << F.getName()
                            << " to cold " << callee->getName() << "\n");
          markFunctionNoCallerSaved(*callee);
          continue;
        }
      }
    }

    if (ColdCallsiteHotCallee) {
      // if callsit is cold and callee is not indirect call and here we
      // create another proxy function call
      if (callee && isColdCallSite(*call) && isFunctionEntryHot(callee)) {
        Function *NF = createProxyFunction(call, *F.getParent());
        if (NF) {
          markFunctionNoCallerSaved(*NF);
          LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
          continue;
        }
      }
    }

    if (HotCallsiteColdCallee) {
      if (call->isIndirectCall()) LLVM_DEBUG(dbgs() << "This is an indirect call!\n");
      if (call->isIndirectCall() && isColdCallSite(*call)) {
        Function *NF = createAndReplaceUsingProxyFunction(call, *F.getParent());
        if (NF) {
          markFunctionNoCallerSaved(*NF);
          LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
          continue;
        }
      }
    }
  }
}

Function* FDOAttrModification2::getCloned(Function* F) {
  if (ClonedFuncs.find(F) != ClonedFuncs.end()) {
    return ClonedFuncs[F];
  } 
  ValueToValueMapTy VMap;
  Function* clone = CloneFunction(F, VMap);
  clone->setName(F->getName() + ".clone");
  ClonedFuncs[F] = clone; 
  if (clone == nullptr) { return nullptr; }
  markFunctionNoCalleeSaved(*clone);
  return clone;
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
      if (isColdCallSite(*call)) {
        Function *callee = call->getCalledFunction();
        if (callee && !callee->isDeclaration() && isFunctionEntryHot(callee)) {
          // if callee is hot on entry
          Function* clone = getCloned(callee);
          if (clone) call->setCalledFunction(clone);
        }
      }
    }
  }
}

static void changeDWARFforFunction(Function &F) {
  if (!F.hasMetadata("dbg")) return;
  auto* metadata = F.getMetadata("dbg");
  auto* node = dyn_cast<DISubprogram>(metadata);
  if (node) {
    // if (node->getNumOperands() >= 3) {
    //   node->replaceLinkageName(MDString::get(F.getContext(), "_Z15no_caller_savedv"));
    // }
    node->replaceOperandWith(2, MDString::get(F.getContext(), F.getName().str()+"(clone)"));
  }
}

bool FDOAttrModification2::runOnModule(Module &M) {
  if (!initProfile()) return false;

  for (auto &F : M) {
    if (F.isDeclaration()) continue;
    initBlockFreqInfo(&F);

    if (UseCalleeReg) CalleeToCaller(F);
    if (UseCallerReg) CallerToCallee(F);

    if (ChangeDWARF) {
      changeDWARFforFunction(F);
    }
  }

  if (OutputPSI != "off") dumpPSI(M);
  LLVM_DEBUG(M.dump());
  LLVM_DEBUG(llvm::verifyModule(M, &dbgs()));
  return false;
}

struct Record {
  std::string name;
  uint64_t freq;
  bool no_caller_saved_registers = false;
  bool no_callee_saved_registers = false;
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
  if (PSI == nullptr) return;

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
        F.hasFnAttribute("no_caller_saved_registers"), 
        F.hasFnAttribute("no_callee_saved_registers"),
        in_hot_list};

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

  std::vector<Record>* buffer[3] = {&hot,  &cold,  &normal };
  std::vector<std::string> names = {"hot", "cold", "normal"};
  std::ofstream fout(path, std::ios_base::out);
  for (int i = 0; i < 3; ++i) {
    fout << names[i] << " functions:" << std::endl;
    for (int j = 0; j < buffer[i]->size(); ++j) {
      Record& c = buffer[i]->at(j);
      fout << (c.no_caller_saved_registers? "* ": "")<< (c.no_callee_saved_registers? "$ ": "") << 
        c.name << " " << c.freq << (c.in_hot_list ? " hl" : "") << std::endl;
    }
  }
}


Pass *createFDOAttrModificationPass() { 
  if (UseNewImpl)
    return new FDOAttrModification(); 
  else 
    return new FDOAttrModification2();
}

}   // namespace llvm
