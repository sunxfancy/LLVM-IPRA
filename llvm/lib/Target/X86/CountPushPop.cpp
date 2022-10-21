#include "MCTargetDesc/X86MCTargetDesc.h"
#include "X86InstrBuilder.h"
#include "X86InstrInfo.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/CodeGen/LazyMachineBlockFrequencyInfo.h"
#include "llvm/InitializePasses.h"
#include "llvm/Option/ArgList.h"
#include "llvm/Support/CommandLine.h"

#include <string>

#define DEBUG_TYPE "count-push-pop"

llvm::cl::opt<std::string>
    EnableCPPP("count-push-pop", llvm::cl::Hidden, llvm::cl::init("off"),
      llvm::cl::ValueOptional, llvm::cl::desc("Enable counting push and pop"));

namespace llvm {

static std::mutex g_file_mutex;

class CountPushPop : public MachineFunctionPass {
public:
  static char ID;
  CountPushPop() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override {
    // printf("run on function %s\n", MF.getName().str().c_str());
    auto PSI = &getAnalysis<ProfileSummaryInfoWrapperPass>().getPSI();
    auto MBFI = (PSI && PSI->hasProfileSummary())
                    ? &getAnalysis<LazyMachineBlockFrequencyInfoPass>().getBFI()
                    : nullptr;
    for (auto &MBB : MF) {
      for (auto &MI : MBB) {
        // MI.getFlag(MachineInstr::FrameSetup) &&
        if (MI.getOpcode() == X86::PUSH64r) {
          if (MBFI) {
            auto p = MBFI->getBlockProfileCount(&MBB);
            if (p)
              PushCount += p.value();
          }
          StaticPushCount += 1;
        } else if (MI.getOpcode() == X86::POP64r) {
          if (MBFI) {
            auto p = MBFI->getBlockProfileCount(&MBB);
            if (p)
              PopCount += p.value();
          }
          StaticPopCount += 1;
        }
      }
    }

    return false;
  }

  uint64_t PushCount;
  uint64_t PopCount;
  uint64_t StaticPushCount;
  uint64_t StaticPopCount;

  bool doInitialization(Module &M) override {
    PushCount = 0;
    PopCount = 0;
    StaticPushCount = 0;
    StaticPopCount = 0;
    return false;
  }

  bool doFinalization(Module &M) override {
    std::lock_guard<std::mutex> guard(g_file_mutex);
    std::string path = EnableCPPP;
    if (path.empty())
      path = "/tmp/count-push-pop.txt";
    FILE *pOut = fopen(path.c_str(), "a");
    if (pOut) {
      fprintf(pOut, "counting in %s\n", M.getName().str().c_str());
      fprintf(pOut, "dynamic push count: %zu\n", PushCount);
      fprintf(pOut, "dynamic pop  count: %zu\n", PopCount);
      fprintf(pOut, "static  push count: %zu\n", StaticPushCount);
      fprintf(pOut, "static  pop  count: %zu\n", StaticPopCount);
      fclose(pOut);
    }
    return false;
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<ProfileSummaryInfoWrapperPass>();
    AU.addRequired<LazyMachineBlockFrequencyInfoPass>();
    AU.setPreservesAll();
    MachineFunctionPass::getAnalysisUsage(AU);
  }
};
} // namespace llvm

char llvm::CountPushPop::ID = 0;
static llvm::RegisterPass<llvm::CountPushPop> X("push-pop-counter",
                                                "Count Push/Pop Pass");

llvm::MachineFunctionPass *createCountPushPopPass() {
  return new llvm::CountPushPop();
}

// INITIALIZE_PASS_BEGIN(CountPushPop, DEBUG_TYPE,
//                       "Count Push and Pop Actions", true, true)
// INITIALIZE_PASS_DEPENDENCY(PEI)
// INITIALIZE_PASS_DEPENDENCY(MachineBlockFrequencyInfo)
// INITIALIZE_PASS_END(CountPushPop, DEBUG_TYPE,
//                     "Count Push and Pop Actions", true, true)
