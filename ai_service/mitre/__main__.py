"""``python -m ai_service.mitre`` : download / refresh the ATT&CK knowledge base now."""

import json
import logging
import sys

from ai_service.mitre.knowledge_base import mitre_kb

logging.basicConfig(level=logging.INFO, format="%(message)s")

ok = mitre_kb.refresh()
print(json.dumps(mitre_kb.status(), indent=2, ensure_ascii=False))
sys.exit(0 if ok else 1)
