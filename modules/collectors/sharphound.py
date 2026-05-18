from modules.opengraph_collectors import (
    CollectorManifest,
    register_collector_manifest,
)


SHARPHOUND_MANIFEST = CollectorManifest(
    source_kind="SharpHound",
    principal_kinds=("User", "Computer", "Group"),
    reserved_labels=("User", "Computer", "Group"),
    merge_strategy="companion_additive",
    allowed_companion_properties=(
        "SMBSigningRequired",
        "collectionSource",
        "disableLoopbackCheck",
        "restrictReceivingNtlmTraffic",
        "storedInSCCMSite",
    ),
    companion_property_prefixes=("SCCM",),
)


register_collector_manifest(SHARPHOUND_MANIFEST)
