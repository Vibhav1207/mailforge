"use client";

import React, { useEffect, useRef, useState } from "react";
import { useInView } from "motion/react";

interface CountUpProps {
  value: string | number;
  duration?: number;
  prefix?: string;
  suffix?: string;
  className?: string;
}

export function CountUp({
  value,
  duration = 1.2,
  prefix = "",
  suffix = "",
  className = "",
}: CountUpProps) {
  const ref = useRef<HTMLSpanElement>(null);
  const isInView = useInView(ref, { once: true, amount: 0.3 });

  // Parse target number and format from the value prop
  const stringVal = String(value);
  const hasPercent = stringVal.includes("%");
  const cleanedVal = stringVal.replace(/[^0-9.]/g, "");
  const targetNumber = parseFloat(cleanedVal) || 0;
  const isDecimal = cleanedVal.includes(".");
  const decimalPlaces = isDecimal ? cleanedVal.split(".")[1].length : 0;
  const hasCommas = stringVal.includes(",");

  const [current, setCurrent] = useState(0);

  useEffect(() => {
    if (!isInView) return;

    // Check for reduced motion preference
    if (typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setCurrent(targetNumber);
      return;
    }

    let startTime: number | null = null;
    let animationFrame: number;

    const easeOutQuad = (t: number) => t * (2 - t);

    const step = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / (duration * 1000), 1);
      const easedProgress = easeOutQuad(progress);

      setCurrent(easedProgress * targetNumber);

      if (progress < 1) {
        animationFrame = requestAnimationFrame(step);
      } else {
        setCurrent(targetNumber);
      }
    };

    animationFrame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animationFrame);
  }, [isInView, targetNumber, duration]);

  const formattedNumber = isDecimal
    ? current.toFixed(decimalPlaces)
    : Math.floor(current).toString();

  const numberWithCommas = hasCommas
    ? formattedNumber.replace(/\B(?=(\d{3})+(?!\d))/g, ",")
    : formattedNumber;

  return (
    <span ref={ref} className={className}>
      {prefix}
      {isInView ? numberWithCommas : (hasCommas ? "0" : (isDecimal ? "0.0" : "0"))}
      {hasPercent && "%"}
      {suffix}
    </span>
  );
}
