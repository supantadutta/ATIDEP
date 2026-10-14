"""Cost-model inputs (blueprint §22): rates, the commercial price register, and the scenario
definitions that make an open-source and a paid configuration functionally comparable.

One rule runs through all of it: **a number needs a source.** A rate, a price, a quantity or a
workload volume is either absent (``None``, and anything that depends on it is reported as
incomplete) or it carries its basis (measured, supplied by the coordinator, or assumed), where it
came from, and, for a supplied value, when it was checked. Nothing here has a default value, so
no figure can enter the analysis by accident. A priced entry also needs the vendor, product,
tier, billing unit, included usage, pricing URL and date; an entry whose price is not public
says so with the fixed wording ``QUOTE_REQUIRED``.
"""

from __future__ import annotations

import re
from datetime import date
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from schemas.common import Strict

QUOTE_REQUIRED = "Vendor quote required / public price unavailable"


class Basis(StrEnum):
    MEASURED = "measured"
    SUPPLIED = "supplied"     # given by the coordinator, from a document or a quotation
    ASSUMED = "assumed"       # a stated assumption; sensitivity analysis varies it


class CostCategory(StrEnum):
    """The common ledger: both scenarios are reported in the same ten categories."""

    SOFTWARE_LICENCE = "software_licence"
    THREAT_INTEL_DATA = "threat_intel_data"
    COMPUTE_INFRASTRUCTURE = "compute_infrastructure"
    HARDWARE = "hardware"
    ENERGY = "energy"
    STORAGE = "storage"
    MODEL_INFERENCE = "model_inference"
    ANALYST_LABOUR = "analyst_labour"
    MAINTENANCE_OPERATIONS = "maintenance_operations"
    DEVELOPMENT = "development"          # one-off build effort; the build view only
    ONBOARDING = "onboarding"            # one-off setup for an adopting organisation
    OTHER = "other"


class UnitKind(StrEnum):
    """What a price is quoted per. A line's quantity driver and the price it uses must agree."""

    MTOK_IN = "mtok_in"                  # per million input tokens
    MTOK_OUT = "mtok_out"                # per million output tokens
    HOUR = "hour"
    MONTH = "month"
    GB_MONTH = "gb_month"                # per gigabyte stored for a month
    GB_INGESTED = "gb_ingested_month"    # per gigabyte of log data ingested in a month
    ENDPOINT_MONTH = "endpoint_month"    # per monitored endpoint per month
    KWH = "kwh"
    ITEM = "item"                        # per report processed


# Hours in an average month (8,760 / 12): a physical constant, used for host capacity.
HOURS_PER_MONTH = 730.0


class Driver(StrEnum):
    """How many units a *rate* line uses per month at a given workload. (A register line is
    driven by the units its chosen product bills in; see ``UnitKind``.)"""

    MONTHLY = "monthly"                  # 1 unit per month
    ANALYST_HOURS = "analyst_hours"      # measured active review hours per item x items
    ENERGY_KWH = "energy_kwh"            # machine hours x loaded wall-socket draw / 1000
    STORAGE_GB = "storage_gb"            # workload assumption
    FIXED_HOURS = "fixed_hours"          # hours per month, or one-off hours (rates / build)


DRIVER_UNIT: dict[Driver, UnitKind] = {
    Driver.MONTHLY: UnitKind.MONTH, Driver.ANALYST_HOURS: UnitKind.HOUR,
    Driver.ENERGY_KWH: UnitKind.KWH, Driver.STORAGE_GB: UnitKind.GB_MONTH,
    Driver.FIXED_HOURS: UnitKind.HOUR,
}


class Perimeter(StrEnum):
    WORKFLOW = "workflow"    # the detection-engineering workflow itself (primary view)
    PLATFORM = "platform"    # plus the detection platform that runs the rules


class Recurrence(StrEnum):
    MONTHLY = "monthly"
    ONE_OFF = "one_off"      # spread straight-line over the horizon, no discounting


class View(StrEnum):
    ADOPT = "adopt"          # an organisation adopting the finished artifact (primary)
    BUILD = "build"          # also counts the one-off development effort


class PriceBasis(StrEnum):
    LIST = "list"
    QUOTE = "quote"
    ACADEMIC = "academic"
    NEGOTIATED = "negotiated"


class Sourced(Strict):
    """A number with its origin. ``value=None`` means "not provided yet"."""

    value: float | None = Field(default=None, ge=0)
    basis: Basis | None = None
    source: str | None = None
    checked_on: date | None = None
    note: str | None = None

    @model_validator(mode="after")
    def _a_number_needs_a_source(self) -> Self:
        if self.value is None:
            return self
        if self.basis is None or not (self.source or "").strip():
            raise ValueError("a value needs its basis (measured, supplied, assumed) and a source")
        if self.basis is Basis.SUPPLIED and self.checked_on is None:
            raise ValueError("a supplied value needs the date it was checked")
        return self

    @property
    def set(self) -> bool:
        return self.value is not None


class FxRate(Strict):
    """One unit of ``from_currency`` is ``rate`` units of ``to_currency``."""

    from_currency: str = Field(pattern=r"^[A-Z]{3}$")
    to_currency: str = Field(pattern=r"^[A-Z]{3}$")
    rate: float = Field(gt=0)
    source: str = Field(min_length=3)
    checked_on: date


class Labour(Strict):
    analyst_hourly: Sourced = Field(default_factory=Sourced)
    engineer_hourly: Sourced = Field(default_factory=Sourced)


class Host(Strict):
    """The machine that runs the open-source stack (owned hardware)."""

    purchase_price: Sourced = Field(default_factory=Sourced)
    useful_life_months: Sourced = Field(default_factory=Sourced)
    project_usage_share: Sourced = Field(default_factory=Sourced)      # 0..1
    # Wall-socket draw under load, measured once with a plug-in meter. The whole loaded draw is
    # attributed to the work (idle draw is not subtracted), which errs against ATIDEP.
    power_active_watts: Sourced = Field(default_factory=Sourced)
    electricity_per_kwh: Sourced = Field(default_factory=Sourced)
    storage_per_gb_month: Sourced = Field(default_factory=Sourced)

    @model_validator(mode="after")
    def _share_is_a_fraction(self) -> Self:
        s = self.project_usage_share.value
        if s is not None and not 0 < s <= 1:
            raise ValueError("project_usage_share must be in (0, 1]")
        return self


class Maintenance(Strict):
    monthly_connector_hours: Sourced = Field(default_factory=Sourced)
    monthly_rule_tuning_hours: Sourced = Field(default_factory=Sourced)
    monthly_platform_admin_hours: Sourced = Field(default_factory=Sourced)


class Build(Strict):
    """One-off hours for the build view and the adopt view (blueprint §22.3)."""

    development_hours: Sourced = Field(default_factory=Sourced)
    adoption_setup_hours: Sourced = Field(default_factory=Sourced)
    integration_hours: Sourced = Field(default_factory=Sourced)   # a paid build's integration


class CostRates(Strict):
    """Rates in the reporting currency. Register prices may be in other currencies and are
    converted with a sourced, dated exchange rate."""

    reporting_currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    fx: list[FxRate] = Field(default_factory=list)
    labour: Labour = Field(default_factory=Labour)
    host: Host = Field(default_factory=Host)
    maintenance: Maintenance = Field(default_factory=Maintenance)
    build: Build = Field(default_factory=Build)
    amortisation_horizon_months: list[int] = Field(min_length=1)

    @field_validator("amortisation_horizon_months")
    @classmethod
    def _positive(cls, v: list[int]) -> list[int]:
        if any(x <= 0 for x in v):
            raise ValueError("horizons are positive month counts")
        return v

    def hardware_monthly(self) -> float | None:
        """Monthly hardware allocation: purchase price x project usage share / useful life
        (blueprint §22.3), in the reporting currency. ``None`` until all three are supplied."""
        h = self.host
        if not (h.purchase_price.set and h.useful_life_months.set and h.project_usage_share.set):
            return None
        if not h.useful_life_months.value:
            return None
        return (h.purchase_price.value * h.project_usage_share.value  # type: ignore[operator]
                / h.useful_life_months.value)

    def rate(self, name: str) -> float | None:
        """The value of a named rate (see ``RATE_UNITS``), or ``None`` if not yet supplied."""
        if name == "derived.hardware_monthly":
            return self.hardware_monthly()
        section, key = name.split(".")
        return getattr(getattr(self, section), key).value

    def convert(self, amount: float, currency: str) -> float | None:
        """``amount`` in ``currency`` expressed in the reporting currency, or ``None`` when no
        sourced exchange rate is on file (a conversion is never guessed)."""
        target = self.reporting_currency
        if target is None:
            return None
        if currency == target:
            return amount
        for r in self.fx:
            if (r.from_currency, r.to_currency) == (currency, target):
                return amount * r.rate
            if (r.from_currency, r.to_currency) == (target, currency):
                return amount / r.rate
        return None


# ---- price register -------------------------------------------------------------------------
class PriceComponent(Strict):
    """One metered part of a product's price (a product may bill input and output tokens, or a
    fee per gigabyte and a fee per endpoint, separately)."""

    unit_kind: UnitKind
    price: float = Field(ge=0)
    billing_unit: str = Field(min_length=2)      # the vendor's own wording
    included_quantity: float = Field(default=0.0, ge=0)   # free each month, in ``unit_kind``
    included_usage_note: str | None = None


class PriceEntry(Strict):
    """One candidate product for one priced requirement (``group``). Every field the coordinator
    asked to preserve for a commercial price is here: vendor and product, source and URL, date
    checked, currency, billing unit, included usage, tier, the workload the tier was chosen for,
    and notes. The calculated cost is not stored here: the ledger writes it per workload."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{2,60}$")
    group: str = Field(pattern=r"^[a-z0-9_]{3,40}$")
    status: Literal["priced", "quote_required"]
    adequate: bool = True            # meets the group's functional requirement at the workload
    adequacy_note: str | None = None   # when not adequate: the logged reason for the exclusion
    vendor: str | None = None
    product: str | None = None
    tier: str | None = None
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    components: list[PriceComponent] = Field(default_factory=list)
    fixed_monthly_fee: float = Field(default=0.0, ge=0)
    pricing_source: str | None = None          # "vendor price page" | "vendor quotation" | ...
    pricing_url: str | None = None
    checked_on: date | None = None             # when the price was retrieved
    price_basis: PriceBasis | None = None      # list | quote | academic | negotiated
    archive_ref: str | None = None             # archived copy: a hash or an archive URL
    workload_assumption: str | None = None     # what usage the tier was chosen for
    notes: str | None = None

    @model_validator(mode="after")
    def _provenance(self) -> Self:
        named = bool((self.vendor or "").strip() and (self.product or "").strip())
        if self.status == "quote_required":
            # No public price. With no vendor named it is a category placeholder: nothing has been
            # chosen yet, and the requirement for the group is written in the notes.
            if self.components or self.fixed_monthly_fee:
                raise ValueError("a quote_required entry carries no price")
            if QUOTE_REQUIRED not in (self.notes or ""):
                raise ValueError(f"a quote_required entry says so in notes: {QUOTE_REQUIRED!r}")
            return self
        if not named:
            raise ValueError("a priced entry names its vendor and product")
        missing = [f for f in ("tier", "currency", "pricing_source", "pricing_url", "checked_on",
                               "workload_assumption") if not getattr(self, f)]
        if not self.components:
            missing.append("components")
        if missing:
            raise ValueError("a priced entry needs " + ", ".join(sorted(missing)))
        kinds = [c.unit_kind for c in self.components]
        if len(kinds) != len(set(kinds)):
            raise ValueError("a unit kind appears once per entry")
        return self

    @property
    def usable(self) -> bool:
        return self.status == "priced" and self.adequate

    @property
    def unit_kinds(self) -> frozenset[UnitKind]:
        return frozenset(c.unit_kind for c in self.components)


class PriceRegister(Strict):
    selection_rule: str = Field(min_length=20)
    entries: list[PriceEntry]

    @model_validator(mode="after")
    def _unique(self) -> Self:
        ids = [e.id for e in self.entries]
        if len(ids) != len(set(ids)):
            raise ValueError("price entry ids must be unique")
        return self

    def group(self, name: str) -> list[PriceEntry]:
        return [e for e in self.entries if e.group == name]

    def groups(self) -> list[str]:
        return sorted({e.group for e in self.entries})


# ---- scenarios ---------------------------------------------------------------------------------
class Function(Strict):
    """A function of the ATIDEP workflow that any comparable build must also perform.

    ``treatment`` says how the paid scenario handles it: ``paid_substitute`` (a paid product does
    it, priced from the register), ``same_component`` (a free component is reused unchanged: a
    rational buyer would use the same open library), ``common_custom_code`` (ATIDEP's own code, the
    same on both sides and listed only so that nothing is silently omitted), ``common_labour``
    (people's time, costed from measured hours) or ``not_applicable``.
    ``equivalence`` says how the technical result is known to match: ``identical`` (same
    component), ``assumed_equal`` (a different product; equal output is an assumption) or
    ``measured`` (the swap's effect is measured)."""

    name: str
    open_source: str
    paid_counterpart: str | None = None
    treatment: Literal["paid_substitute", "same_component", "common_custom_code",
                       "common_labour", "not_applicable"]
    equivalence: Literal["identical", "assumed_equal", "measured"]


class PriceRef(Strict):
    source: Literal["register", "rate", "free"]
    ref: str | None = None           # register group, or a name from RATE_UNITS
    licence: str | None = None       # for "free": the licence that makes the charge zero


# Rates a line can name, and what each is quoted per.
RATE_UNITS: dict[str, UnitKind] = {
    "labour.analyst_hourly": UnitKind.HOUR, "labour.engineer_hourly": UnitKind.HOUR,
    "host.electricity_per_kwh": UnitKind.KWH, "host.storage_per_gb_month": UnitKind.GB_MONTH,
    "derived.hardware_monthly": UnitKind.MONTH,
}
# The quantity ``fixed_hours`` lines may name.
FIXED_HOUR_QUANTITIES = ("maintenance.monthly_connector_hours",
                         "maintenance.monthly_rule_tuning_hours",
                         "maintenance.monthly_platform_admin_hours",
                         "build.development_hours", "build.adoption_setup_hours",
                         "build.integration_hours")
# Categories whose hours are *operating* labour (differential between scenarios). Review labour
# (analyst_labour) is common to the automated scenarios and is excluded from the comparison.
OPERATING_CATEGORIES = (CostCategory.MAINTENANCE_OPERATIONS, CostCategory.DEVELOPMENT,
                        CostCategory.ONBOARDING)


class Line(Strict):
    id: str = Field(pattern=r"^[a-z0-9_]{3,40}$")
    function: str
    covers: list[str] = Field(default_factory=list)    # other functions a bundled product covers
    category: CostCategory
    perimeter: Perimeter = Perimeter.WORKFLOW
    recurrence: Recurrence = Recurrence.MONTHLY
    views: list[View] = Field(default_factory=lambda: [View.ADOPT, View.BUILD], min_length=1)
    price: PriceRef
    # Only a rate line has a driver; a register line is driven by the units its chosen product
    # bills in, and a free line costs nothing.
    driver: Driver | None = None
    quantity_ref: str | None = None      # for the fixed_hours driver
    note: str | None = None

    @model_validator(mode="after")
    def _price_reference(self) -> Self:
        p = self.price
        if p.source == "free":
            if not (p.licence or "").strip():
                raise ValueError("a free line names the licence that makes it free")
            if self.driver:
                raise ValueError("a free line has no driver")
        elif not p.ref:
            raise ValueError("a register or rate price needs a reference")
        if p.source == "register" and self.driver:
            raise ValueError("a register line is driven by its product's billing units")
        if p.source == "rate":
            if self.driver is None:
                raise ValueError("a rate line needs a driver")
            if p.ref not in RATE_UNITS:
                raise ValueError(f"unknown rate {p.ref!r}")
            if DRIVER_UNIT[self.driver] != RATE_UNITS[p.ref]:
                raise ValueError(f"driver {self.driver} and rate {p.ref} are in different units")
            if (self.driver is Driver.FIXED_HOURS) != (self.quantity_ref is not None):
                raise ValueError("only fixed_hours lines carry a quantity_ref, and they need one")
            if self.quantity_ref and self.quantity_ref not in FIXED_HOUR_QUANTITIES:
                raise ValueError(f"unknown quantity {self.quantity_ref!r}")
        if self.recurrence is Recurrence.ONE_OFF and self.category not in OPERATING_CATEGORIES \
                and self.category is not CostCategory.OTHER:
            raise ValueError("only development, onboarding and other costs are one-off")
        return self

    @property
    def functions(self) -> set[str]:
        return {self.function, *self.covers}


class NotRequired(Strict):
    function: str
    reason: str = Field(min_length=10)


class Scenario(Strict):
    """A configuration being costed. Names avoid the experimental conditions (A, B, C, B-V, B-R):
    ``S-MANUAL`` is condition A, ``S-OSS-LOCAL`` is condition B, ``S-OSS-API`` is condition B on a
    paid model (measured only if that arm is run), and ``S-PAID`` is a component-substitution
    counterfactual with no condition."""

    id: str = Field(pattern=r"^S-[A-Z0-9]+(-[A-Z0-9]+)*$")
    name: str
    description: str
    backend: Literal["local", "cloud", "manual"]
    review_condition: Literal["A", "B"]      # whose analyst minutes are this scenario's review
    lines: list[Line]
    not_required: list[NotRequired] = Field(default_factory=list)

    @model_validator(mode="after")
    def _lines_unique(self) -> Self:
        ids = [ln.id for ln in self.lines]
        if len(ids) != len(set(ids)):
            raise ValueError(f"scenario {self.id}: line ids must be unique")
        return self


class Workload(Strict):
    id: str = Field(pattern=r"^[a-z0-9_]{3,30}$")
    description: str
    basis: str = Field(min_length=15)          # why this scale; never blank
    items_per_month: Sourced
    storage_gb: Sourced = Field(default_factory=Sourced)
    siem_ingest_gb_per_month: Sourced = Field(default_factory=Sourced)
    monitored_endpoints: Sourced = Field(default_factory=Sourced)

    @model_validator(mode="after")
    def _volume(self) -> Self:
        if not self.items_per_month.set or self.items_per_month.value == 0:
            raise ValueError("a workload states its volume (items per month)")
        return self


class CostScenarios(Strict):
    functions: dict[str, Function]
    scenarios: list[Scenario]
    workloads: list[Workload]
    oss_local: str                         # the ATIDEP scenario as built
    oss_api: str                           # the same pipeline on a paid hosted model
    paid: str                              # the paid counterpart (modelled)
    manual: str                            # the manual workflow

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        for fid in self.functions:
            if not re.fullmatch(r"FN[0-9]+", fid):
                raise ValueError(f"function ids look like FN1, not {fid!r}")
        ids = [s.id for s in self.scenarios]
        if len(ids) != len(set(ids)):
            raise ValueError("scenario ids must be unique")
        for ref in (self.oss_local, self.oss_api, self.paid, self.manual):
            if ref not in ids:
                raise ValueError(f"unknown scenario {ref!r}")
        if len({w.id for w in self.workloads}) != len(self.workloads):
            raise ValueError("workload ids must be unique")
        for s in self.scenarios:
            for ln in s.lines:
                unknown = ln.functions - set(self.functions)
                if unknown:
                    raise ValueError(f"{s.id}/{ln.id}: unknown function {sorted(unknown)}")
            for nr in s.not_required:
                if nr.function not in self.functions:
                    raise ValueError(f"{s.id}: unknown function {nr.function}")
        # Comparability: the two automated scenarios account for every function.
        for sid in (self.oss_local, self.paid):
            missing = self.uncovered(sid)
            if missing:
                raise ValueError(f"{sid} leaves functions unaccounted for: {missing}")
        # A function priced as a paid substitute must have a register line in the paid scenario.
        priced = {f for ln in self.scenario(self.paid).lines if ln.price.source == "register"
                  for f in ln.functions}
        for fid, fn in self.functions.items():
            if fn.treatment == "paid_substitute" and fid not in priced:
                raise ValueError(f"{fid} is a paid substitute but {self.paid} has no priced "
                                 "line for it")
        return self

    def scenario(self, sid: str) -> Scenario:
        return next(s for s in self.scenarios if s.id == sid)

    def workload(self, wid: str) -> Workload:
        return next(w for w in self.workloads if w.id == wid)

    def uncovered(self, sid: str) -> list[str]:
        """Functions the scenario neither costs nor declares not required. A scenario with any
        is not comparable to the others (the comparability check)."""
        sc = self.scenario(sid)
        covered = {f for ln in sc.lines for f in ln.functions} | {n.function
                                                                  for n in sc.not_required}
        return sorted(set(self.functions) - covered)
