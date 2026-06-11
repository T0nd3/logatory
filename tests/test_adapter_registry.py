from logatory.adapters import (
    AdapterSpec,
    available_adapters,
    fleet_target_types,
    get_adapter_class,
    get_adapter_spec,
    register_adapter,
)
from logatory.adapters.base import SourceAdapter
from logatory.adapters.file import FileAdapter


class TestBuiltinRegistry:
    def test_all_builtins_registered(self):
        names = set(available_adapters())
        assert names == {
            "file",
            "stdin",
            "tail",
            "journald",
            "docker",
            "ssh",
            "loki",
            "graylog",
            "opensearch",
        }

    def test_get_adapter_class_returns_the_class(self):
        assert get_adapter_class("file") is FileAdapter

    def test_unknown_name_returns_none(self):
        assert get_adapter_class("nope") is None
        assert get_adapter_spec("nope") is None

    def test_fleet_targets_exclude_stdin_and_tail(self):
        fleet = fleet_target_types()
        assert "stdin" not in fleet
        assert "tail" not in fleet
        assert "file" in fleet
        assert "graylog" in fleet

    def test_registered_classes_are_source_adapters(self):
        for name in available_adapters():
            cls = get_adapter_class(name)
            assert cls is not None
            assert issubclass(cls, SourceAdapter)


class TestRegisterAdapter:
    def test_register_and_lookup_roundtrip(self):
        class CustomAdapter(SourceAdapter):
            async def events(self):  # pragma: no cover - never iterated here
                return
                yield

        try:
            register_adapter(AdapterSpec("custom-test", CustomAdapter, fleet_target=False))
            assert get_adapter_class("custom-test") is CustomAdapter
            assert "custom-test" in available_adapters()
            assert "custom-test" not in fleet_target_types()
        finally:
            # keep the module-level registry clean for other tests
            from logatory.adapters import _REGISTRY

            _REGISTRY.pop("custom-test", None)


def test_fleet_builders_match_registry_targets():
    """Every fleet builder maps to a fleet-targetable registry entry, and vice
    versa — so adding a source can't leave the two halves out of sync."""
    from logatory.fleet.factory import _BUILDERS

    assert set(_BUILDERS) == fleet_target_types()
