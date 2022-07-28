
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/CodeGen/LazyMachineBlockFrequencyInfo.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/RegisterUsageInfo.h"
#include "llvm/CodeGen/TargetFrameLowering.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

#define DEBUG_TYPE "fdo-ipra"

STATISTIC(NumCSROpt,
          "Number of functions optimized for callee saved registers");

namespace llvm {

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

class FDOAttrModification2 : public FunctionPass {
public:
  FDOAttrModification2() : FunctionPass(ID) {}

  StringRef getPassName() const override {
    return "FDO based Attributes Modification Pass";
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<ProfileSummaryInfoWrapperPass>();
    AU.setPreservesAll();
    FunctionPass::getAnalysisUsage(AU);
  }

  bool runOnFunction(Function &MF) override;

protected:
  static char ID;
};

char FDOAttrModification2::ID = 0;

bool FDOAttrModification2::runOnFunction(Function &MF) {
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
          if (MI.getOpcode() == Instruction::Call) {
            Function *callee = dyn_cast<CallInst>(&MI)->getCalledFunction();
            LLVM_DEBUG(dbgs() << "callee: " << callee->getName() << "\n");
            if (callee == nullptr || callee->isDeclaration())
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

Pass *createFDOAttrModification2Pass() { return new FDOAttrModification2(); }

} // namespace llvm