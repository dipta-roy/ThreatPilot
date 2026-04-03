"""Diagram exporter module for ThreatPilot.

Provides logic to render and export the current architecture diagram along 
with all its identified overlays (components, flows, etc.) to an image file.
"""

from __future__ import annotations
from pathlib import Path
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QImage, QPainter
from PySide6.QtWidgets import QGraphicsScene

def export_scene_to_image(scene: QGraphicsScene, output_path: str | Path) -> None:
    """Render the entire graphics scene into a high-quality image file.

    Captures the background diagram and all vector overlays (boxes, arrows,
    labels) exactly as they appear in the editor.

    Args:
        scene: The active QGraphicsScene containing the diagram.
        output_path: Destination path for the image (typically .png).

    Raises:
        OSError: If the image cannot be saved.
        ValueError: If the scene is empty.
    """
    scene_rect = scene.itemsBoundingRect()
    if scene_rect.isEmpty():
        raise ValueError("Cannot export an empty diagram scene.")

    image = QImage(
        scene_rect.width(),
        scene_rect.height(),
        QImage.Format.Format_ARGB32
    )
    image.fill(Qt.GlobalColor.white)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    scene.render(painter, QRectF(image.rect()), scene_rect)
    painter.end()

    if not image.save(str(output_path)):
        raise OSError(f"Failed to save diagram image to {output_path}")