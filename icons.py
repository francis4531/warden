"""Cute planet icons for agents. A small themed set the user picks from; if none is
chosen, one is assigned deterministically so every agent still gets a face."""

# order matters: this is the palette shown in the picker
PLANETS = [
    ("saturn", "Saturn"), ("earth", "Earth"), ("mars", "Mars"), ("neptune", "Neptune"),
    ("jupiter", "Jupiter"), ("venus", "Venus"), ("moon", "Moon"), ("alien", "Verdant"),
    ("violet", "Violet"), ("star", "Star"), ("sun", "Sol"), ("comet", "Comet"),
]

_SHINE = '<circle cx="15" cy="15" r="3" fill="#fff" opacity=".35"/>'

SVG = {
    "saturn": '<svg viewBox="0 0 40 40"><ellipse cx="20" cy="21" rx="17" ry="5" fill="none" stroke="#e0b357" stroke-width="2.4" opacity=".5"/><circle cx="20" cy="20" r="11" fill="#f2c56b"/><path d="M3 21 a17 5 0 0 0 34 0" fill="none" stroke="#e0b357" stroke-width="2.4"/>' + _SHINE + '</svg>',
    "earth":  '<svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="12" fill="#4a90d9"/><path d="M11 15 q5 -2 8 1 q3 3 -2 5 q-5 1 -6 -3 z" fill="#5cba6b"/><path d="M25 21 q4 0 4 3 q-1 3 -5 1 z" fill="#5cba6b"/>' + _SHINE + '</svg>',
    "mars":   '<svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="12" fill="#d9663a"/><circle cx="16" cy="18" r="2" fill="#b04e2a"/><circle cx="25" cy="23" r="2.6" fill="#b04e2a"/><circle cx="23" cy="15" r="1.5" fill="#b04e2a"/>' + _SHINE + '</svg>',
    "neptune":'<svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="12" fill="#3f5fc4"/><path d="M9 18 q11 -3 22 0" stroke="#2c46a0" stroke-width="2" fill="none"/><path d="M10 23 q10 -2 20 0" stroke="#2c46a0" stroke-width="2" fill="none"/>' + _SHINE + '</svg>',
    "jupiter":'<svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="12" fill="#e0a56a"/><path d="M9 16 h22" stroke="#c98a4e" stroke-width="2.4"/><path d="M8 22 h24" stroke="#c98a4e" stroke-width="2"/><ellipse cx="24" cy="23" rx="2.6" ry="1.9" fill="#c0533a"/>' + _SHINE + '</svg>',
    "venus":  '<svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="12" fill="#e9c98a"/><path d="M10 20 q10 -4 20 0" stroke="#d3ac63" stroke-width="2" fill="none"/><path d="M12 25 q8 -3 16 0" stroke="#d3ac63" stroke-width="1.8" fill="none"/>' + _SHINE + '</svg>',
    "moon":   '<svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="12" fill="#c7ccd6"/><circle cx="16" cy="16" r="2.5" fill="#a7adba"/><circle cx="25" cy="22" r="3" fill="#a7adba"/><circle cx="20" cy="26" r="1.8" fill="#a7adba"/>' + _SHINE + '</svg>',
    "alien":  '<svg viewBox="0 0 40 40"><ellipse cx="20" cy="21" rx="16" ry="4.5" fill="none" stroke="#6fbf60" stroke-width="2.2" opacity=".55"/><circle cx="20" cy="20" r="11" fill="#8fd97d"/><path d="M4 21 a16 4.5 0 0 0 32 0" fill="none" stroke="#6fbf60" stroke-width="2.2"/>' + _SHINE + '</svg>',
    "violet": '<svg viewBox="0 0 40 40"><circle cx="20" cy="20" r="12" fill="#9b6fd4"/><circle cx="25" cy="24" r="3" fill="#7d55b8"/><circle cx="15" cy="24" r="1.8" fill="#7d55b8"/>' + _SHINE + '</svg>',
    "star":   '<svg viewBox="0 0 40 40"><path d="M20 7 l3.4 8.2 8.9 .7 -6.8 5.7 2.1 8.6 -7.6 -4.6 -7.6 4.6 2.1 -8.6 -6.8 -5.7 8.9 -.7 z" fill="#f2c94c"/></svg>',
    "sun":    '<svg viewBox="0 0 40 40"><g stroke="#f2b035" stroke-width="2.2" stroke-linecap="round"><line x1="20" y1="4" x2="20" y2="8"/><line x1="20" y1="32" x2="20" y2="36"/><line x1="4" y1="20" x2="8" y2="20"/><line x1="32" y1="20" x2="36" y2="20"/><line x1="9" y1="9" x2="12" y2="12"/><line x1="28" y1="28" x2="31" y2="31"/><line x1="31" y1="9" x2="28" y2="12"/><line x1="12" y1="28" x2="9" y2="31"/></g><circle cx="20" cy="20" r="8.5" fill="#f7c948"/></svg>',
    "comet":  '<svg viewBox="0 0 40 40"><path d="M30 10 L14 26" stroke="#8fd0f0" stroke-width="3" stroke-linecap="round" opacity=".6"/><path d="M27 13 L17 23" stroke="#bfe6f7" stroke-width="2" stroke-linecap="round" opacity=".8"/><circle cx="28" cy="12" r="6" fill="#5cc0e8"/><circle cx="26" cy="10" r="2" fill="#fff" opacity=".5"/></svg>',
}

_KEYS = [k for k, _ in PLANETS]

def default_for(seed):
    """Deterministic pick so every agent gets a consistent icon even without choosing."""
    h = 0
    for ch in str(seed or ""):
        h = (h * 31 + ord(ch)) & 0xffffffff
    return _KEYS[h % len(_KEYS)]

def svg(key, seed=None):
    if key not in SVG:
        key = default_for(seed if seed is not None else key)
    return SVG[key]
