"""Diagram canvas widget for ThreatPilot.

Provides a feature-rich ``QGraphicsView`` subclass with:
- Mouse-wheel zoom (anchored under cursor)
- Middle-button / Ctrl+click pan
- Fit-to-screen
- Overlay items: component bounding boxes, flow arrows, trust boundaries
"""

from __future__ import annotations

from enum import Enum, auto
from typing import Any

from PySide6.QtCore import Qt, QPointF, QRectF, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QPolygonF,
    QWheelEvent,
)
from PySide6.QtWidgets import (
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsPathItem,
    QGraphicsPixmapItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QWidget,
)


# ======================================================================
# Constants
# ======================================================================

_ZOOM_IN_FACTOR: float = 1.15
_ZOOM_OUT_FACTOR: float = 1.0 / _ZOOM_IN_FACTOR
_MIN_ZOOM: float = 0.05
_MAX_ZOOM: float = 20.0


# ======================================================================
# Overlay style enums
# ======================================================================


class OverlayKind(Enum):
    """Visual kind for an overlay item."""

    COMPONENT_BOX = auto()
    FLOW_ARROW = auto()
    TRUST_BOUNDARY = auto()


# Colour palette for overlays (semi-transparent)
_OVERLAY_COLORS: dict[OverlayKind, QColor] = {
    OverlayKind.COMPONENT_BOX: QColor(100, 180, 255, 160),
    OverlayKind.FLOW_ARROW: QColor(255, 180, 60, 200),
    OverlayKind.TRUST_BOUNDARY: QColor(180, 100, 255, 100),
}


# ======================================================================
# DiagramCanvas
# ======================================================================


class DiagramCanvas(QGraphicsView):
    """Interactive diagram canvas with zoom, pan, and overlay support.

    Signals:
        item_selected: Emitted when a graphics item is selected.
            Carries the item or ``None`` when the selection is cleared.
        zoom_changed: Emitted when the zoom level changes.
            Carries the current zoom factor as a float.
    """

    item_selected: Signal = Signal(object)  # QGraphicsItem | None
    zoom_changed: Signal = Signal(float)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, parent: QWidget | None = None) -> None:
        self._scene = QGraphicsScene(parent)
        super().__init__(self._scene, parent)

        self._current_zoom: float = 1.0
        self._diagram_pixmap_item: QGraphicsPixmapItem | None = None
        self._overlay_items: list[QGraphicsItem] = []
        self._is_panning: bool = False
        self._pan_start: QPointF = QPointF()

        self._configure_view()

    # ------------------------------------------------------------------
    # View configuration
    # ------------------------------------------------------------------

    def _configure_view(self) -> None:
        """Apply default rendering and interaction settings."""
        self.setRenderHints(
            QPainter.RenderHint.Antialiasing
            | QPainter.RenderHint.SmoothPixmapTransform
        )
        self.setTransformationAnchor(
            QGraphicsView.ViewportAnchor.AnchorUnderMouse
        )
        self.setResizeAnchor(
            QGraphicsView.ViewportAnchor.AnchorViewCenter
        )
        self.setViewportUpdateMode(
            QGraphicsView.ViewportUpdateMode.SmartViewportUpdate
        )
        self.setDragMode(QGraphicsView.DragMode.NoDrag)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setBackgroundBrush(QBrush(QColor("#11111b")))

    # ------------------------------------------------------------------
    # Zoom
    # ------------------------------------------------------------------

    def wheelEvent(self, event: QWheelEvent) -> None:  # noqa: N802
        """Zoom in / out using the mouse wheel.

        The zoom is anchored under the cursor position.
        """
        angle = event.angleDelta().y()
        if angle == 0:
            return

        factor = _ZOOM_IN_FACTOR if angle > 0 else _ZOOM_OUT_FACTOR
        new_zoom = self._current_zoom * factor

        if new_zoom < _MIN_ZOOM or new_zoom > _MAX_ZOOM:
            return

        self.scale(factor, factor)
        self._current_zoom = new_zoom
        self.zoom_changed.emit(self._current_zoom)

    def zoom_in(self) -> None:
        """Zoom in by one step."""
        new_zoom = self._current_zoom * _ZOOM_IN_FACTOR
        if new_zoom <= _MAX_ZOOM:
            self.scale(_ZOOM_IN_FACTOR, _ZOOM_IN_FACTOR)
            self._current_zoom = new_zoom
            self.zoom_changed.emit(self._current_zoom)

    def zoom_out(self) -> None:
        """Zoom out by one step."""
        new_zoom = self._current_zoom * _ZOOM_OUT_FACTOR
        if new_zoom >= _MIN_ZOOM:
            self.scale(_ZOOM_OUT_FACTOR, _ZOOM_OUT_FACTOR)
            self._current_zoom = new_zoom
            self.zoom_changed.emit(self._current_zoom)

    def reset_zoom(self) -> None:
        """Reset zoom to 1:1."""
        self.resetTransform()
        self._current_zoom = 1.0
        self.zoom_changed.emit(self._current_zoom)

    @property
    def current_zoom(self) -> float:
        """Return the current zoom factor."""
        return self._current_zoom

    # ------------------------------------------------------------------
    # Pan (middle-button or Ctrl+left-button)
    # ------------------------------------------------------------------

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        """Begin panning on middle-button or Ctrl+left press."""
        if (
            event.button() == Qt.MouseButton.MiddleButton
            or (
                event.button() == Qt.MouseButton.LeftButton
                and event.modifiers() & Qt.KeyboardModifier.ControlModifier
            )
        ):
            self._is_panning = True
            self._pan_start = event.position()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        """Continue panning while the button is held."""
        if self._is_panning:
            delta = event.position() - self._pan_start
            self._pan_start = event.position()
            self.horizontalScrollBar().setValue(
                self.horizontalScrollBar().value() - int(delta.x())
            )
            self.verticalScrollBar().setValue(
                self.verticalScrollBar().value() - int(delta.y())
            )
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        """End panning on button release."""
        if self._is_panning:
            self._is_panning = False
            self.setCursor(Qt.CursorShape.ArrowCursor)
            event.accept()
            return
        super().mouseReleaseEvent(event)

    # ------------------------------------------------------------------
    # Fit to screen
    # ------------------------------------------------------------------

    def fit_to_screen(self) -> None:
        """Fit the entire scene content to the viewport, keeping aspect ratio."""
        rect = self._scene.sceneRect()
        if rect.isNull() or rect.isEmpty():
            return
        self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
        # Recalculate current zoom from the resulting transform
        self._current_zoom = self.transform().m11()
        self.zoom_changed.emit(self._current_zoom)

    # ------------------------------------------------------------------
    # Diagram image
    # ------------------------------------------------------------------

    def set_diagram_pixmap(self, pixmap: QPixmap) -> None:
        """Display a diagram image, replacing any previous one.

        Args:
            pixmap: The ``QPixmap`` to display.
        """
        # Remove previous diagram (keep overlays)
        if self._diagram_pixmap_item is not None:
            self._scene.removeItem(self._diagram_pixmap_item)
            self._diagram_pixmap_item = None

        self._diagram_pixmap_item = self._scene.addPixmap(pixmap)
        self._diagram_pixmap_item.setZValue(-100)  # behind overlays
        self._scene.setSceneRect(QRectF(pixmap.rect()))
        self.fit_to_screen()

    def clear_diagram(self) -> None:
        """Remove the diagram image and all overlays."""
        self.clear_overlays()
        if self._diagram_pixmap_item is not None:
            self._scene.removeItem(self._diagram_pixmap_item)
            self._diagram_pixmap_item = None

    @property
    def diagram_pixmap_item(self) -> QGraphicsPixmapItem | None:
        """Return the current diagram pixmap item, or ``None``."""
        return self._diagram_pixmap_item

    # ------------------------------------------------------------------
    # Overlay management
    # ------------------------------------------------------------------

    def add_component_box(
        self,
        rect: QRectF,
        label: str = "",
        *,
        color: QColor | None = None,
        data: Any = None,
    ) -> QGraphicsRectItem:
        """Add a component bounding box overlay.

        Args:
            rect: Bounding rectangle in scene coordinates.
            label: Optional text label displayed in the top-left corner.
            color: Optional override colour; defaults to the component palette.
            data: Arbitrary data to attach to the item (e.g. component ID).

        Returns:
            The ``QGraphicsRectItem`` added to the scene.
        """
        c = color or _OVERLAY_COLORS[OverlayKind.COMPONENT_BOX]
        pen = QPen(c, 2)
        brush = QBrush(QColor(c.red(), c.green(), c.blue(), 40))

        box = self._scene.addRect(rect, pen, brush)
        box.setZValue(10)
        box.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        if data is not None:
            box.setData(0, data)

        if label:
            text_item = QGraphicsSimpleTextItem(label, box)
            text_item.setBrush(QBrush(c))
            font = QFont("Segoe UI", 9, QFont.Weight.Bold)
            text_item.setFont(font)
            text_item.setPos(rect.x() + 4, rect.y() + 2)

        self._overlay_items.append(box)
        return box

    def add_flow_arrow(
        self,
        start: QPointF,
        end: QPointF,
        label: str = "",
        *,
        color: QColor | None = None,
        data: Any = None,
    ) -> QGraphicsPathItem:
        """Add a data-flow arrow overlay between two points.

        Args:
            start: Start point (source component) in scene coordinates.
            end: End point (target component) in scene coordinates.
            label: Optional text label placed at the midpoint.
            color: Optional override colour.
            data: Arbitrary data to attach to the item.

        Returns:
            The ``QGraphicsPathItem`` added to the scene.
        """
        c = color or _OVERLAY_COLORS[OverlayKind.FLOW_ARROW]
        pen = QPen(c, 2)

        # Build path: line + arrowhead
        path = QPainterPath()
        path.moveTo(start)
        path.lineTo(end)

        # Arrowhead
        arrow_size = 10.0
        dx = end.x() - start.x()
        dy = end.y() - start.y()
        length = (dx * dx + dy * dy) ** 0.5
        if length > 0:
            ux, uy = dx / length, dy / length
            # perpendicular
            px, py = -uy, ux
            tip = end
            left = QPointF(
                tip.x() - arrow_size * ux + arrow_size * 0.4 * px,
                tip.y() - arrow_size * uy + arrow_size * 0.4 * py,
            )
            right = QPointF(
                tip.x() - arrow_size * ux - arrow_size * 0.4 * px,
                tip.y() - arrow_size * uy - arrow_size * 0.4 * py,
            )
            path.addPolygon(QPolygonF([tip, left, right, tip]))

        item = self._scene.addPath(path, pen, QBrush(c))
        item.setZValue(15)
        item.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        if data is not None:
            item.setData(0, data)

        if label:
            mid = QPointF((start.x() + end.x()) / 2, (start.y() + end.y()) / 2)
            text_item = QGraphicsSimpleTextItem(label, item)
            text_item.setBrush(QBrush(c))
            font = QFont("Segoe UI", 8)
            text_item.setFont(font)
            text_item.setPos(mid.x() + 4, mid.y() - 12)

        self._overlay_items.append(item)
        return item

    def add_trust_boundary(
        self,
        rect: QRectF,
        label: str = "",
        *,
        color: QColor | None = None,
        data: Any = None,
    ) -> QGraphicsRectItem:
        """Add a trust-boundary rectangle overlay.

        Trust boundaries are drawn as dashed rectangles behind
        component boxes but above the diagram image.

        Args:
            rect: Bounding rectangle in scene coordinates.
            label: Optional label displayed at the top of the boundary.
            color: Optional override colour.
            data: Arbitrary data to attach.

        Returns:
            The ``QGraphicsRectItem`` added to the scene.
        """
        c = color or _OVERLAY_COLORS[OverlayKind.TRUST_BOUNDARY]
        pen = QPen(c, 2, Qt.PenStyle.DashLine)
        brush = QBrush(QColor(c.red(), c.green(), c.blue(), 25))

        box = self._scene.addRect(rect, pen, brush)
        box.setZValue(5)  # behind component boxes
        box.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        if data is not None:
            box.setData(0, data)

        if label:
            text_item = QGraphicsSimpleTextItem(label, box)
            text_item.setBrush(QBrush(c))
            font = QFont("Segoe UI", 10, QFont.Weight.Bold)
            text_item.setFont(font)
            text_item.setPos(rect.x() + 6, rect.y() - 18)

        self._overlay_items.append(box)
        return box

    def clear_overlays(self) -> None:
        """Remove all overlay items (keeps the diagram image)."""
        for item in self._overlay_items:
            self._scene.removeItem(item)
        self._overlay_items.clear()

    @property
    def overlay_items(self) -> list[QGraphicsItem]:
        """Return the current list of overlay items."""
        return list(self._overlay_items)

    # ------------------------------------------------------------------
    # Scene accessor
    # ------------------------------------------------------------------

    @property
    def graphics_scene(self) -> QGraphicsScene:
        """Return the underlying ``QGraphicsScene``."""
        return self._scene
