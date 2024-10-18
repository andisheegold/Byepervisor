.intel_syntax noprefix
.text

.global _start, _hen_bin_start, _hen_bin_end

_hen_bin_start:
.incbin HEN_BIN_PATH
_hen_bin_end: