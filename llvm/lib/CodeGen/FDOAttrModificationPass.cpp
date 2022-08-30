
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
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
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CallGraph.h"

using namespace llvm;

#define DEBUG_TYPE "fdo-ipra"

static cl::opt<bool> OnHotEntryAndHotCallGraph("fdoipra-both-hot", cl::init(false), cl::Hidden);
static cl::opt<bool> ColdCallsiteColdCallee("fdoipra-cc", cl::init(true), cl::Hidden);
static cl::opt<bool> ColdCallsiteHotCallee ("fdoipra-ch", cl::init(true), cl::Hidden);
static cl::opt<bool> HotCallsiteColdCallee ("fdoipra-hc", cl::init(false), cl::Hidden);
static cl::opt<bool> HotCallsiteHotCallee  ("fdoipra-hh", cl::init(false), cl::Hidden);

namespace llvm {

// This implementation has bugs
class FDOAttrModification : public MachineFunctionPass {
public:
  FDOAttrModification() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "FDO based Attributes Modification Pass";
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<ProfileSummaryInfoWrapperPass>();
    AU.setPreservesAll();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

protected:
  Function *get_callee(const MachineInstr &MI);

  static char ID;
};

char FDOAttrModification::ID = 0;

Function *FDOAttrModification::get_callee(const MachineInstr &MI) {
  for (unsigned i = 0; i < MI.getNumOperands(); ++i) {
    auto &op = MI.getOperand(i);
    // op.dump();
    if (op.isGlobal() && isa<Function>(op.getGlobal())) {
      return const_cast<Function *>(dyn_cast<Function>(op.getGlobal()));
    }
  }
  return nullptr;
}

bool FDOAttrModification::runOnMachineFunction(MachineFunction &MF) {
  auto PSI = &getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
  bool has_profile = PSI && PSI->hasProfileSummary();
  if (has_profile) {
    LLVM_DEBUG(dbgs() << "caller has profile: " << MF.getName() << "\n");
    LLVM_DEBUG(dbgs() << "hot threshod = " << PSI->getHotCountThreshold()
                      << "\n");
    LLVM_DEBUG(dbgs() << "func addr: " << (&MF.getFunction())
                      << "  func count: "
                      << MF.getFunction().getEntryCount()->getCount() << "\n");
    // this is a hot function
    if (PSI->isFunctionEntryHot(&MF.getFunction())) {
      LLVM_DEBUG(dbgs() << "hot caller: " << MF.getName() << "\n");
      for (auto &MBB : MF)
        for (auto &MI : MBB)
          if (MI.isCall()) {
            Function *callee = get_callee(MI);
            LLVM_DEBUG(dbgs() << "callee: " << callee->getName() << "\n");
            if (callee->isDeclaration())
              break;
            LLVM_DEBUG(dbgs() << "cold callee: " << callee->getName() << "\n");
            // if callee is cold
            if (PSI->isFunctionEntryCold(callee)) {
              LLVM_DEBUG(dbgs() << "Adding attributes from hot " << MF.getName()
                                << " to cold " << callee->getName() << "\n");
              if (callee->hasFnAttribute("no_caller_saved_registers") ==
                  false) {
                callee->addFnAttr("no_caller_saved_registers");
                LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
              }
            }
          }
    }
  }

  return false;
}

Pass *createFDOAttrModificationPass() { return new FDOAttrModification(); }

class FDOAttrModification2 : public ModulePass {
public:
  FDOAttrModification2() : ModulePass(ID) {}

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
};

char FDOAttrModification2::ID = 0;


static Function* createProxyFunction(CallInst* Call, Module& M) {
  Function* F = Call->getCalledFunction();
  if (F == nullptr) {
    LLVM_DEBUG(dbgs() << "createProxyFunction Failed: " << *Call << "\n");
    return nullptr;
  }
  std::string name = F->getName().str();
  std::string new_name = name + "$NCSRProxy";
  LLVM_DEBUG(dbgs() << "createProxyFunction: " << new_name << "\n");
  LLVM_DEBUG(dbgs() << "createProxyFunction: " << *F << "\n");
  auto NF = M.getOrInsertFunction(new_name, F->getFunctionType(), F->getAttributes());
  LLVM_DEBUG(dbgs() << *(NF.getFunctionType()) << "\n";);
  LLVM_DEBUG(dbgs() << *(NF.getCallee()) << "\n";);
  Call->setCalledFunction(NF);
  return dyn_cast<Function>(NF.getCallee());
}


bool FDOAttrModification2::runOnModule(Module &M) {
  auto PSI = &getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
  bool has_profile = PSI && PSI->hasProfileSummary();
  if (has_profile) {
    for (auto& F : M) {
      if (F.isDeclaration()) continue;
      auto& BFI = getAnalysis<BlockFrequencyInfoWrapperPass>(F).getBFI();

      // if this is a not hot function
      if (OnHotEntryAndHotCallGraph) {
        if (!PSI->isFunctionEntryHot(&F) && !PSI->isFunctionHotInCallGraph(&F, BFI)) continue;
      } else {
        if (!PSI->isFunctionEntryHot(&F)) continue;
      }

      LLVM_DEBUG(dbgs() << "caller has profile: " << F.getName() << "\n");
      LLVM_DEBUG(dbgs() << "hot threshod = " << PSI->getHotCountThreshold() << "\n");
      LLVM_DEBUG(dbgs() << "func addr: " << (&F.getFunction())
                        << "  func count: " << F.getFunction().getEntryCount()->getCount() << "\n");
      
      LLVM_DEBUG(dbgs() << "hot caller: " << F.getName() << "\n");

      for (auto &BB : F)
        for (auto &MI : BB)
          if (MI.getOpcode() == Instruction::Call) {
            CallInst *call = dyn_cast<CallInst>(&MI);
            Function *callee = call->getCalledFunction();
            LLVM_DEBUG(dbgs() << "callee: " << callee->getName() << "\n");
            if (callee == nullptr || callee->isDeclaration())
              break;

            if (ColdCallsiteColdCallee) {
              // if callee is cold on entry
              if (PSI->isFunctionEntryCold(callee)) {
                LLVM_DEBUG(dbgs() << "Adding attributes from hot " << F.getName()
                                  << " to cold " << callee->getName() << "\n");
                if (callee->hasFnAttribute("no_caller_saved_registers") ==
                    false) {
                  callee->addFnAttr("no_caller_saved_registers");
                  LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
                }
              }
            }

            if (ColdCallsiteHotCallee) {
              auto callsite = BFI.getBlockProfileCount(&BB);
              // if callsit is cold and callee is not indirect call and   here we create another proxy function call
              if (callsite.has_value() && callsite.value() < 50 && callee && PSI->isFunctionEntryHot(callee)) {
                Function* NF = createProxyFunction(call, M);
                if (NF && NF->hasFnAttribute("no_caller_saved_registers") == false) {
                  NF->addFnAttr("no_caller_saved_registers");
                  LLVM_DEBUG(dbgs() << "set no caller saved registers\n");
                }
              }
            }

            if (HotCallsiteColdCallee) {
              auto callsite = BFI.getBlockProfileCount(&BB);
              if (call->isIndirectCall() && callsite.value() < 50) {
                
              }
            }
          }
    }
  }

  return false;
}

Pass *createFDOAttrModification2Pass() { return new FDOAttrModification2(); }

} // namespace llvm