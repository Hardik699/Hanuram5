import { useEffect } from "react";
import { createPortal } from "react-dom";

interface ModalProps {
  children: React.ReactNode;
  onClose?: () => void;
  className?: string;
}

export default function Modal({ children, onClose, className = "" }: ModalProps) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose?.();
    };
    document.addEventListener("keydown", onKey);

    // Mark document as modal-open so layout can disable header blur
    document.documentElement.classList.add("modal-open");
    // Prevent body scroll
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      document.removeEventListener("keydown", onKey);
      document.documentElement.classList.remove("modal-open");
      document.body.style.overflow = prevOverflow || "";
    };
  }, [onClose]);

  const modal = (
    <div className={`fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-3 sm:p-4 backdrop-blur-sm`}>
      <div
        onClick={(e) => e.stopPropagation()}
        className={`relative ${className}`}
      >
        {children}
      </div>
    </div>
  );

  const el = document.getElementById("modal-root");
  if (el) return createPortal(modal, el);
  // fallback to body
  return createPortal(modal, document.body);
}
