CC=gcc
LD=ld
LDFLAGS=-lcapstone -lkeystone
SRC=morph_table_builder.c
TRG=morph_table_builder
NO_MORPH=slotmachine_no_morph
MORPH_TBL=slotmachine_morph_tbl.s

.PHONY: clean all

default: $(MORPH_TBL)

$(TRG): $(SRC)
	$(CC) -o $@ $^ $(LDFLAGS)

$(MORPH_TBL): $(TRG) $(NO_MORPH)
	./$(TRG) $(filter-out $<,$^) > $@

clean:
	-rm $(TRG) $(MORPH_TBL)
