"""Runtime registry assembled from event-module declarations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .catalog import Catalog, ModuleDecl
from .events import ParsedEvent, ProjectionContext, ProjectionResult
from .state import StateStore
from .event_modules.connection import registry_meta as connection_meta
from .event_modules.content_message import codec as message_codec
from .event_modules.content_message import projector as message_projector
from .event_modules.content_message import registry_meta as message_meta
from .event_modules.content_user import codec as user_codec
from .event_modules.content_user import projector as user_projector
from .event_modules.content_user import registry_meta as user_meta
from .event_modules.pipeline_boundary import registry_meta as pipeline_meta
from .event_modules.sender_boundary import registry_meta as sender_meta
from .event_modules.sync_need import codec as need_codec
from .event_modules.sync_need import projector as need_projector
from .event_modules.sync_need import registry_meta as need_meta


Parser = Callable[[str, bytes, dict, str | None], ParsedEvent]
Projector = Callable[[ProjectionContext, StateStore], ProjectionResult]


@dataclass(frozen=True)
class RuntimeEventModule:
    module_id: str
    parse: Parser
    project: Projector


@dataclass(frozen=True)
class RuntimeRegistry:
    catalog: Catalog
    event_modules: dict[str, RuntimeEventModule]

    def module_for_event(self, event_type: str) -> RuntimeEventModule:
        try:
            return self.event_modules[event_type]
        except KeyError as exc:
            raise ValueError(f"unknown event type {event_type}") from exc


def build_registry() -> RuntimeRegistry:
    module_decls: tuple[ModuleDecl, ...] = (
        pipeline_meta.declaration(),
        connection_meta.declaration(),
        user_meta.declaration(),
        message_meta.declaration(),
        sender_meta.declaration(),
        need_meta.declaration(),
    )
    catalog = Catalog.from_modules(module_decls)
    return RuntimeRegistry(
        catalog=catalog,
        event_modules={
            user_meta.EVENT_TYPE: RuntimeEventModule(
                module_id=user_meta.MODULE_ID,
                parse=user_codec.parse,
                project=lambda context, _store: user_projector.project(context),
            ),
            message_meta.EVENT_TYPE: RuntimeEventModule(
                module_id=message_meta.MODULE_ID,
                parse=message_codec.parse,
                project=lambda context, _store: message_projector.project(context),
            ),
            need_meta.EVENT_TYPE: RuntimeEventModule(
                module_id=need_meta.MODULE_ID,
                parse=need_codec.parse,
                project=need_projector.project,
            ),
        },
    )
