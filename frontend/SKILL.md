---
name: design-system-sec1-sast-world-s-most-advanced-ai
description: Creates implementation-ready design-system guidance with tokens, component behavior, and accessibility standards. Use when creating or updating UI rules, component specifications, or design-system documentation.
---

<!-- TYPEUI_SH_MANAGED_START -->

# Sec1 SAST — World's Most Advanced AI

## Mission
Deliver implementation-ready design-system guidance for Sec1 SAST — World's Most Advanced AI that can be applied consistently across marketing site interfaces.

## Brand
- Product/brand: Sec1 SAST — World's Most Advanced AI
- URL: https://sec1.io/sastng/
- Audience: buyers, teams, and decision-makers
- Product surface: marketing site

## Style Foundations
- Visual style: structured, accessible, implementation-first
- Main font style: `font.family.primary=Inter`, `font.family.stack=Inter, sans-serif`, `font.size.base=16px`, `font.weight.base=400`, `font.lineHeight.base=27.2px`
- Typography scale: `font.size.xs=12.48px`, `font.size.sm=12.8px`, `font.size.md=13px`, `font.size.lg=13.12px`, `font.size.xl=13.44px`, `font.size.2xl=13.6px`, `font.size.3xl=15.2px`, `font.size.4xl=16px`
- Color palette: `color.border.default=#ffffff`, `color.text.secondary=#454d68`, `color.text.tertiary=#04060b`, `color.text.inverse=#2a3048`, `color.surface.base=#000000`, `color.surface.strong=#ff4a14`, `color.border.muted=rgb(4, 6, 11) rgb(4, 6, 11) rgb(232, 234, 242)`, `color.border.strong=#6b7394`
- Spacing scale: `space.1=2.71px`, `space.2=3px`, `space.3=4px`, `space.4=6px`, `space.5=8px`, `space.6=10px`, `space.7=12px`, `space.8=14px`
- Radius/shadow/motion tokens: `radius.xs=10px`, `radius.sm=14px`, `radius.md=16px`, `radius.lg=24px` | `shadow.1=rgba(255, 74, 20, 0.3) 0px 8px 32px 0px`, `shadow.2=rgba(0, 0, 0, 0.15) 0px 4px 24px 0px`, `shadow.3=rgba(0, 0, 0, 0.04) 0px 4px 32px 0px`, `shadow.4=rgba(196, 61, 16, 0.3) 0px 8px 32px 0px` | `motion.duration.instant=300ms`, `motion.duration.fast=400ms`, `motion.duration.normal=500ms`, `motion.duration.slow=600ms`

## Accessibility
- Target: WCAG 2.2 AA
- Keyboard-first interactions required.
- Focus-visible rules required.
- Contrast constraints required.

## Writing Tone
concise, confident, implementation-focused

## Rules: Do
- Use semantic tokens, not raw hex values in component guidance.
- Every component must define required states: default, hover, focus-visible, active, disabled, loading, error.
- Responsive behavior and edge-case handling should be specified for every component family.
- Accessibility acceptance criteria must be testable in implementation.

## Rules: Don't
- Do not allow low-contrast text or hidden focus indicators.
- Do not introduce one-off spacing or typography exceptions.
- Do not use ambiguous labels or non-descriptive actions.

## Guideline Authoring Workflow
1. Restate design intent in one sentence.
2. Define foundations and tokens.
3. Define component anatomy, variants, and interactions.
4. Add accessibility acceptance criteria.
5. Add anti-patterns and migration notes.
6. End with QA checklist.

## Required Output Structure
- Context and goals
- Design tokens and foundations
- Component-level rules (anatomy, variants, states, responsive behavior)
- Accessibility requirements and testable acceptance criteria
- Content and tone standards with examples
- Anti-patterns and prohibited implementations
- QA checklist

## Component Rule Expectations
- Include keyboard, pointer, and touch behavior.
- Include spacing and typography token requirements.
- Include long-content, overflow, and empty-state handling.

## Quality Gates
- Every non-negotiable rule must use "must".
- Every recommendation should use "should".
- Every accessibility rule must be testable in implementation.
- Prefer system consistency over local visual exceptions.

<!-- TYPEUI_SH_MANAGED_END -->
