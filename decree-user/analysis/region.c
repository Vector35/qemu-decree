#include "qemu.h"
#include "asmx86/asmx86.h"

struct region_definition {
    uint32_t begin, end;
    uint32_t index;
    char *description;
};

static uint32_t next_region_index = 1;

static int region_filter(CPUArchState *env, void *data, abi_ulong pc, struct Instruction *insn)
{
    struct region_definition *def = (struct region_definition*)data;
    if ((pc == def->begin) || (pc == def->end))
        return 1;
    return 0;
}

static void region_before_insn(CPUArchState *env, void *data, abi_ulong insn_eip, struct Instruction *insn)
{
    struct region_definition *def = (struct region_definition*)data;
    char name[64];

    if (insn_eip == def->begin) {
        sprintf(name, "start%d", def->index);
    } else {
        sprintf(name, "end%d", def->index);
    }

    analysis_output_log(env, name, def->description);
}

static int activate_region(CPUArchState *env, int argc, char **argv)
{
    if (argc < 2)
        return 0;

    struct region_definition *def = (struct region_definition*)malloc(sizeof(struct region_definition));
    def->begin = strtoul(argv[0], NULL, 16);
    def->end = strtoul(argv[1], NULL, 16);
    def->index = next_region_index++;

    size_t len = 1;
    size_t i;
    for (i = 2; i < argc; i++) {
        len += strlen(argv[i]) + 1;
    }

    def->description = (char*)malloc(len);
    def->description[0] = 0;
    for (i = 2; i < argc; i++) {
        if (i > 2)
            strcat(def->description, ",");
        strcat(def->description, argv[i]);
    }

    add_insn_instrumentation(env, region_filter, region_before_insn, NULL, def);
    return 1;
}

void init_region_analysis(void)
{
    register_analysis_type("region", "Tracks entry and exit to a region of code", activate_region);
}
