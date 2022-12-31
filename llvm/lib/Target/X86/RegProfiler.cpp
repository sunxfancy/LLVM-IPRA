#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/CodeGen/LazyMachineBlockFrequencyInfo.h"
#include "llvm/InitializePasses.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/IR/GlobalValue.h"
#include <string>
#include <fstream>

#define DEBUG_TYPE "reg-profiler"

llvm::cl::opt<bool>
  EnablePPP("EnablePushPopProfile", llvm::cl::Hidden, llvm::cl::init(false),
            llvm::cl::ValueOptional, llvm::cl::desc("Enable counting push and pop"));

llvm::cl::opt<bool>
  EnableSBP("EnableSpillBytesProfile", llvm::cl::Hidden, llvm::cl::init(false),
            llvm::cl::ValueOptional, llvm::cl::desc("Enable counting spill bytes"));

namespace llvm {

struct PPCounts {
  uint64_t Push = 0;
  uint64_t Pop = 0;
  uint64_t StaticPush = 0;
  uint64_t StaticPop = 0;
};

struct SBCounts {
  uint64_t Spill = 0;
  uint64_t Reload = 0;
  uint64_t StaticSpill = 0;
  uint64_t StaticReload = 0;
};

class InstrumentRegProfilerPass : public MachineFunctionPass {
public:
  static char ID;
  llvm::GlobalValue *SpillReg, *Spill, *Reload, *Push, *Pop;

  InstrumentRegProfilerPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override {
    LLVM_DEBUG(dbgs() << "Reg profiler run on function " << MF.getName() << "\n");
    LLVM_DEBUG(MF.getFunction().print(dbgs()));
    LLVM_DEBUG(MF.print(dbgs()));
    const auto &TII = *MF.getSubtarget().getInstrInfo();
    llvm::GlobalValue* vars[4] = {Push, Pop, Spill, Reload};
    const unsigned push = 0, pop = 1, spill = 2, reload = 3;

    for (auto &MBB : MF) {
      unsigned count[4] = {0, 0, 0, 0};
      for (auto &MI : MBB) {
        if (EnablePPP) {
          if (MI.getOpcode() == X86::PUSH64r) {
            count[push]++;
          } else if (MI.getOpcode() == X86::POP64r) {
            count[pop]++;
          } 
        } 
        if (EnableSBP) {
          Optional<unsigned> Size;
          if (Size = MI.getSpillSize(&TII)) {
            LLVM_DEBUG(dbgs() << "SpillInst: ";  MI.print(dbgs()));
            count[spill] += Size.getValue();
          } else if (Size = MI.getRestoreSize(&TII)) {
            LLVM_DEBUG(dbgs() << "ReloadInst: ";  MI.print(dbgs()));
            count[reload] += Size.getValue();
          }
        }
      }
      if (count[push] == 0 && count[pop] == 0 && count[spill] == 0 && count[reload] == 0) continue;
      
      auto dbgLoc = MBB.begin()->getDebugLoc();
      auto it = MBB.begin();
      // here add the profiling code for profiling
      for (int i = 0; i < 4; ++i) {
        if (count[i] == 0) continue;
        if (count[i] < 128)
          MBB.insert(it, BuildMI(MF, dbgLoc, TII.get(X86::ADD64mi8))
            .addReg(X86::NoRegister).addImm(1).addReg(X86::NoRegister).addGlobalAddress(vars[i], 0, X86II::MO_TPOFF).addReg(X86::FS).addImm(count[i]));
        else
          MBB.insert(it, BuildMI(MF, dbgLoc, TII.get(X86::ADD64mi32))
            .addReg(X86::NoRegister).addImm(1).addReg(X86::NoRegister).addGlobalAddress(vars[i], 0, X86II::MO_TPOFF).addReg(X86::FS).addImm(count[i]));
      }
    }
    LLVM_DEBUG(MF.print(dbgs()));
    return true;
  }

  bool doInitialization(Module &M) override {
    SpillReg = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_SpillReg", Type::getInt64Ty(M.getContext())));
    Spill = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_Spill", Type::getInt64Ty(M.getContext())));
    Reload = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_Reload", Type::getInt64Ty(M.getContext())));
    Push = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_Push", Type::getInt64Ty(M.getContext())));
    Pop = dyn_cast<GlobalValue>(M.getOrInsertGlobal("__LLVM_IRPP_Pop", Type::getInt64Ty(M.getContext())));
    return true;
  }

  // bool doInitialization(Module &M) override {
  //   auto Ty = Type::getInt64Ty(M.getContext());
  //   auto createGlobal = [&M, Ty](StringRef name) {
  //     return dyn_cast<GlobalValue>(M.getOrInsertGlobal(name, Ty, [=] {
  //       return new GlobalVariable(Ty, false, GlobalVariable::ExternalLinkage,
  //                               nullptr, name, GlobalValue::ThreadLocalMode::GeneralDynamicTLSModel);
  //     }));
  //   };
  //   Spill = createGlobal("__LLVM_IRPP_Spill");
  //   Reload = createGlobal("__LLVM_IRPP_Reload");
  //   Push = createGlobal("__LLVM_IRPP_Push");
  //   Pop = createGlobal("__LLVM_IRPP_Pop");
  //   return true;
  // }

  bool doFinalization(Module &M) override {
    return false;
  }
};
} // namespace llvm

char llvm::InstrumentRegProfilerPass::ID = 0;
static llvm::RegisterPass<llvm::InstrumentRegProfilerPass> X("instrument-reg-profiler",
                                                "Instrument reg profiler pass");

llvm::MachineFunctionPass *createInstrumentRegProfilerPassPass() {
  return new llvm::InstrumentRegProfilerPass();
}
