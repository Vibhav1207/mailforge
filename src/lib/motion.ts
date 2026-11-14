import { type Transition, type Variants } from "motion/react";

// Standard Motion Timings & Easings (Resend/Vercel/Linear style)
export const MOTION_EASE = [0.16, 1, 0.3, 1] as const;
export const MOTION_EASE_OUT = [0, 0, 0.2, 1] as const;
export const MOTION_EASE_IN_OUT = [0.4, 0, 0.2, 1] as const;

export const TRANSITION_FAST: Transition = {
  duration: 0.18,
  ease: MOTION_EASE,
};

export const TRANSITION_NORMAL: Transition = {
  duration: 0.25,
  ease: MOTION_EASE,
};

export const TRANSITION_SECTION: Transition = {
  duration: 0.45,
  ease: MOTION_EASE,
};

export const TRANSITION_HERO: Transition = {
  duration: 0.65,
  ease: MOTION_EASE,
};

export const TRANSITION_SPRING = {
  type: "spring" as const,
  stiffness: 400,
  damping: 30,
};

// Reusable Variants
export const fadeInVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: TRANSITION_NORMAL,
  },
};

export const fadeUpVariants: Variants = {
  hidden: { opacity: 0, y: 16 },
  visible: {
    opacity: 1,
    y: 0,
    transition: TRANSITION_SECTION,
  },
};

export const heroEntranceVariants: Variants = {
  hidden: { opacity: 0, y: 24 },
  visible: {
    opacity: 1,
    y: 0,
    transition: TRANSITION_HERO,
  },
};

export const staggerContainerVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.08,
      delayChildren: 0.05,
    },
  },
};

export const staggerFastVariants: Variants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
      delayChildren: 0.02,
    },
  },
};

export const cardHoverVariants = {
  rest: { y: 0, transition: TRANSITION_FAST },
  hover: { y: -2, transition: TRANSITION_FAST },
};

export const buttonMotionProps = {
  whileHover: { y: -1.5, transition: TRANSITION_FAST },
  whileTap: { scale: 0.97, transition: { duration: 0.1 } },
};

export const modalBackdropVariants: Variants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { duration: 0.2 } },
  exit: { opacity: 0, transition: { duration: 0.15 } },
};

export const modalContentVariants: Variants = {
  hidden: { opacity: 0, scale: 0.96, y: 8 },
  visible: {
    opacity: 1,
    scale: 1,
    y: 0,
    transition: { duration: 0.22, ease: MOTION_EASE },
  },
  exit: {
    opacity: 0,
    scale: 0.97,
    y: 4,
    transition: { duration: 0.15, ease: MOTION_EASE_OUT },
  },
};
