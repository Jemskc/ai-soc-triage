import { useState, useRef, useEffect, useCallback } from 'react';

// A box the analyst can drag taller.
//
// The raw log panes were locked to max-h-52 (208px). That is fine for a
// one-line authentication record and useless for a 40-line Sysmon event or a
// long command line — the thing you most need to read whole is exactly the
// thing that overflows. Rather than pick a taller fixed number and be wrong in
// the other direction, let the person reading it decide.
//
// The chosen height is remembered per pane in localStorage, so it survives
// collapsing a row, paging, and reloading. Storage is wrapped because it
// throws in a private window and the pane must still render.

const PREFIX = 'soc:pane:';

function readStored(key, fallback) {
  try {
    const n = parseInt(window.localStorage.getItem(PREFIX + key), 10);
    return Number.isFinite(n) ? n : fallback;
  } catch {
    return fallback;
  }
}

function writeStored(key, value) {
  try {
    window.localStorage.setItem(PREFIX + key, String(value));
  } catch {
    /* private window, or storage disabled — the size just won't persist */
  }
}

export default function ResizablePane({
  storageKey,
  defaultHeight = 208,
  minHeight = 64,
  maxHeight = 1600,
  className = '',
  children,
}) {
  const clamp = useCallback(
    h => Math.min(Math.max(Math.round(h), minHeight), maxHeight),
    [minHeight, maxHeight],
  );

  const [height, setHeight] = useState(() =>
    clamp(readStored(storageKey, defaultHeight)));
  const [dragging, setDragging] = useState(false);
  const start = useRef({ y: 0, h: 0 });

  function beginDrag(e) {
    e.preventDefault();
    start.current = { y: e.clientY, h: height };
    setDragging(true);
  }

  // Listeners go on the window, not the handle: the pointer routinely leaves
  // the 8px handle mid-drag, and a handle-local listener would drop the drag
  // the moment it did.
  useEffect(() => {
    if (!dragging) return undefined;

    const onMove = e => setHeight(clamp(start.current.h + (e.clientY - start.current.y)));
    const onUp = () => setDragging(false);

    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onUp);

    // Without this, dragging downward selects every line of the log text.
    const priorSelect = document.body.style.userSelect;
    const priorCursor = document.body.style.cursor;
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'ns-resize';

    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      document.body.style.userSelect = priorSelect;
      document.body.style.cursor = priorCursor;
    };
  }, [dragging, clamp]);

  // Persist only when the drag ends, so a single stretch is one write rather
  // than one per pixel of mouse travel.
  useEffect(() => {
    if (!dragging) writeStored(storageKey, height);
  }, [dragging, height, storageKey]);

  function resetHeight() {
    setHeight(clamp(defaultHeight));
  }

  // Keyboard equivalent, for the same reason the rest of the app has focus
  // styles: a resize that only a mouse can perform is not available to
  // everyone.
  function onKeyDown(e) {
    const step = e.shiftKey ? 80 : 16;
    if (e.key === 'ArrowDown') { e.preventDefault(); setHeight(h => clamp(h + step)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setHeight(h => clamp(h - step)); }
    else if (e.key === 'Home') { e.preventDefault(); resetHeight(); }
  }

  return (
    <div className="relative">
      <div className={`overflow-auto ${className}`} style={{ height: `${height}px` }}>
        {children}
      </div>
      <div
        role="separator"
        aria-orientation="horizontal"
        aria-label="Resize panel"
        tabIndex={0}
        onPointerDown={beginDrag}
        onDoubleClick={resetHeight}
        onKeyDown={onKeyDown}
        title="Drag to resize · double-click to reset"
        className={`group h-2 mt-0.5 flex items-center justify-center cursor-ns-resize rounded
                    focus:outline-none focus:ring-1 focus:ring-blue-500
                    ${dragging ? 'bg-blue-500/20' : 'hover:bg-hover'}`}
      >
        <span
          className={`h-0.5 w-8 rounded-full transition-colors
                      ${dragging ? 'bg-blue-400' : 'bg-border group-hover:bg-blue-400'}`}
        />
      </div>
    </div>
  );
}
