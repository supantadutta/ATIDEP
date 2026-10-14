"""Offline economic evaluation (blueprint §22).

The application records quantities and prices nothing. This package turns the exported
quantities, the rates, the price register and the scenarios into costs, and refuses to put a
number where an input is missing: a cost that depends on an unsupplied rate, an unpriced product
or an unmeasured quantity is reported as incomplete, with the exact list of what is missing, and
never as zero.
"""
