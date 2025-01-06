#TOOLCHAIN=aarch64-unknown-linux-gnu-
CC=$(TOOLCHAIN)gcc
AS=$(TOOLCHAIN)as
LD=$(TOOLCHAIN)ld
MAKE=make

ASMSRC=slotmachine.s
BIN=$(ASMSRC:.s=.o)
VIR=slotmachine

VIR_NO_MORPH_SRC=slotmachine_no_morph.s
VIR_NO_MORPH_BIN=$(VIR_NO_MORPH_SRC:.s=.o)
VIR_NO_MORPH=$(MORPH_DIR)/slotmachine_no_morph

QEMU=qemu-aarch64
QEMU_ARGS=-strace
STRACE=strace

EVO_DIR=evolution_chamber
MORPH_DIR=morph_table_builder
SRC_DIR=virus_src
TRG_DIR=targets
TEST_BIN=target_arm64_17

.PHONY: clean all run

all: $(VIR_NO_MORPH) $(VIR)

run: $(VIR_NO_MORPH) $(VIR)
	-mkdir $(EVO_DIR)/test
	cp slotmachine $(EVO_DIR)/test
	cp $(TRG_DIR)/$(TEST_BIN) $(EVO_DIR)/test_bin
	cp $(TRG_DIR)/target_arm64_broken_0 $(EVO_DIR)/test
	cp $(TRG_DIR)/target_arm64_broken_1 $(EVO_DIR)/test
	cp $(TRG_DIR)/target_arm64_broken_2 $(EVO_DIR)/test
	cp $(TRG_DIR)/target_arm64_broken_3 $(EVO_DIR)/test
	cd $(EVO_DIR) && ./evolution_test.sh

$(VIR_NO_MORPH_SRC):
	cat $(SRC_DIR)/slotmachine_meat.s > $@
	cat $(MORPH_DIR)/slotmachine_morph_tbl_no_morph.s >> $@
	cat $(SRC_DIR)/slotmachine_tail.s >> $@

$(ASMSRC):
	cd $(MORPH_DIR) && $(MAKE)
	cat $(SRC_DIR)/slotmachine_meat.s > $@
	cat $(MORPH_DIR)/slotmachine_morph_tbl.s >> $@
	cat $(SRC_DIR)/slotmachine_tail.s >> $@

%.o: %.s
	$(AS) $^ -o $@

$(VIR_NO_MORPH): $(VIR_NO_MORPH_SRC) $(VIR_NO_MORPH_BIN)
	$(LD) $(filter-out $<,$^) -o $@

$(VIR): $(ASMSRC) $(BIN)
	$(LD) $(filter-out $<,$^) -o $@

clean:
	-rm $(ASMSRC) $(BIN) $(VIR)
	-rm $(EVO_DIR)/slotmachine $(EVO_DIR)/test/*
	-rm $(VIR_NO_MORPH_BIN) $(VIR_NO_MORPH_SRC) $(VIR_NO_MORPH)
	cd $(MORPH_DIR) && $(MAKE) clean
