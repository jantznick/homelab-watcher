import { useEffect } from "react";

/**
 * Refcounted page scroll lock for custom modals.
 *
 * Locks `document.documentElement` + `document.body` (the real scroll
 * containers in this Vite app — `#root` / `.app` are not overflow scrollers).
 * Nested modals increment the count; unlock only when the last closes.
 */

let lockCount = 0;
let savedBodyOverflow = "";
let savedHtmlOverflow = "";
let savedBodyPaddingRight = "";
let savedBodyTouchAction = "";
let wheelBlocker: ((e: WheelEvent) => void) | null = null;
let touchBlocker: ((e: TouchEvent) => void) | null = null;

function isInsideModalPanel(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;
  return Boolean(target.closest(".modal-panel, .drawer-panel"));
}

function applyLock() {
  if (lockCount !== 0) return;
  const gap = window.innerWidth - document.documentElement.clientWidth;
  savedBodyOverflow = document.body.style.overflow;
  savedHtmlOverflow = document.documentElement.style.overflow;
  savedBodyPaddingRight = document.body.style.paddingRight;
  savedBodyTouchAction = document.body.style.touchAction;

  document.documentElement.style.overflow = "hidden";
  document.body.style.overflow = "hidden";
  document.body.style.touchAction = "none";
  document.documentElement.classList.add("modal-scroll-lock");
  document.body.classList.add("modal-scroll-lock");
  if (gap > 0) {
    document.body.style.paddingRight = `${gap}px`;
  }

  wheelBlocker = (e: WheelEvent) => {
    if (isInsideModalPanel(e.target)) return;
    e.preventDefault();
  };
  touchBlocker = (e: TouchEvent) => {
    if (isInsideModalPanel(e.target)) return;
    e.preventDefault();
  };
  document.addEventListener("wheel", wheelBlocker, { passive: false, capture: true });
  document.addEventListener("touchmove", touchBlocker, { passive: false, capture: true });
}

function releaseLock() {
  if (lockCount !== 0) return;
  document.documentElement.style.overflow = savedHtmlOverflow;
  document.body.style.overflow = savedBodyOverflow;
  document.body.style.paddingRight = savedBodyPaddingRight;
  document.body.style.touchAction = savedBodyTouchAction;
  document.documentElement.classList.remove("modal-scroll-lock");
  document.body.classList.remove("modal-scroll-lock");
  if (wheelBlocker) {
    document.removeEventListener("wheel", wheelBlocker, true);
    wheelBlocker = null;
  }
  if (touchBlocker) {
    document.removeEventListener("touchmove", touchBlocker, true);
    touchBlocker = null;
  }
}

/** Call with `open` from Settings / Modal — safe for nested dialogs. */
export function useScrollLock(locked: boolean) {
  useEffect(() => {
    if (!locked) return;
    applyLock();
    lockCount += 1;
    return () => {
      lockCount = Math.max(0, lockCount - 1);
      releaseLock();
    };
  }, [locked]);
}
