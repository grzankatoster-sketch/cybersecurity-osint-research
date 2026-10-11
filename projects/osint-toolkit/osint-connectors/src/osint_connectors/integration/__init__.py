"""Warstwa integracji z konsumentami wyników (np. model sprawy entity-graph).

Ta warstwa nie importuje entity-graph — produkuje neutralne struktury zgodne z
jego kontraktem (``RunRecord.to_dict()``), aby uniknąć sprzężenia i nie dotykać
jego kodu. To konsument (entity-graph) importuje osint-connectors, nie odwrotnie.
"""
from .case_mapping import ENTITY_GRAPH_RUN_KEYS, finding_to_run, findings_to_runs

__all__ = ["finding_to_run", "findings_to_runs", "ENTITY_GRAPH_RUN_KEYS"]
