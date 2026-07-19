<?php

declare(strict_types=1);

namespace LoginDefense\Core;

/**
 * The three states of the escalation ladder. Kept as a first-class enum so the
 * decision is an auditable value, not a scattering of magic strings or booleans.
 */
enum Outcome
{
    case Allow;
    case RequireCaptcha;
    case Lockout;
}
