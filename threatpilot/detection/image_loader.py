"""Image loader for ThreatPilot.

Handles importing a user-selected PNG / JPG image into a project and
loading it into a ``QGraphicsScene`` for display on the diagram canvas.
"""

from __future__ import annotations
import shutil
from pathlib import Path
from PySide6.QtCore import Qt, QRectF
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import QGraphicsPixmapItem, QGraphicsScene, QGraphicsView
from threatpilot.core.diagram_model import Diagram

SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({".png", ".jpg", ".jpeg"})

def import_diagram_file(
    source_path: str | Path,
    project_path: str | Path,
) -> Diagram:
    """Copy an image file into the project ``diagrams/`` folder and
    return a corresponding ``Diagram`` metadata object.

    The file is copied (not moved) so that the user's original is
    preserved.  The destination filename is ``<diagram_id>_<original>``.

    Args:
        source_path: Absolute path to the user's image file.
        project_path: Root path of the current project directory.

    Returns:
        A ``Diagram`` instance with metadata populated (including image
        dimensions).

    Raises:
        FileNotFoundError: If *source_path* does not exist.
        ValueError: If the file extension is not PNG or JPG.
    """
    src = Path(source_path)
    if not src.is_file():
        raise FileNotFoundError(f"Image file not found: {src}")

    ext = src.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported image format '{ext}'. "
            f"Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    diagram = Diagram.create(
        original_name=src.name,
        file_path="",
    )

    dest_name = f"{diagram.diagram_id}_{src.name}"
    diagrams_dir = Path(project_path) / "diagrams"
    diagrams_dir.mkdir(parents=True, exist_ok=True)
    dest = diagrams_dir / dest_name

    img = QImage(str(src))
    if not img.isNull():
        MAX_SIZE = 4096
        if img.width() > MAX_SIZE or img.height() > MAX_SIZE:
            img = img.scaled(
                MAX_SIZE,
                MAX_SIZE,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
            img.save(str(dest))
        else:
            shutil.copy2(str(src), str(dest))
            
        diagram.width = img.width()
        diagram.height = img.height()
    else:
        shutil.copy2(str(src), str(dest))

    diagram.file_path = f"diagrams/{dest_name}"
    return diagram


def load_diagram_to_scene(
    diagram: Diagram,
    project_path: str | Path,
    scene: QGraphicsScene,
    view: QGraphicsView | None = None,
) -> QGraphicsPixmapItem | None:
    """Load a diagram image into a ``QGraphicsScene``.

    Any existing items in the scene are removed first so that only one
    diagram is displayed at a time.

    Args:
        diagram: The ``Diagram`` whose image should be shown.
        project_path: Root path of the project directory.
        scene: The ``QGraphicsScene`` to add the pixmap to.
        view: Optional ``QGraphicsView``; when provided the view is
            fitted to the image after loading.

    Returns:
        The ``QGraphicsPixmapItem`` that was added, or ``None`` if the
        image could not be loaded.
    """
    image_path = Path(project_path) / diagram.file_path
    if not image_path.is_file():
        return None

    pixmap = QPixmap(str(image_path))
    if pixmap.isNull():
        return None

    scene.clear()
    item = scene.addPixmap(pixmap)
    scene.setSceneRect(QRectF(pixmap.rect()))

    if view is not None:
        view.fitInView(scene.sceneRect(), mode=1)

    return item
