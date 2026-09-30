/* The PayGuard hooded figure: one original SVG drawing (made for this project; a reference photo was used only
   for pose and mood), shared by the landing page and the scan-result "sentinel".
   Colours come from CSS variables on the container: --rim-a, --rim-b (edge light), --eyes (0..1), --eye (eye colour). */
(() => {
  "use strict";
  let n = 0;
  function svg(opts = {}) {
    const id = "h" + (++n);
    const u = k => `${k}-${id}`;
    const laptop = opts.laptop ? `
      <path class="laptop" d="M150 590 L450 590 L474 720 L126 720 Z" fill="url(#${u("lid")})"/>
      <path d="M150 590 L450 590" stroke="url(#${u("rim")})" stroke-width="2" opacity=".8"/>
      <g class="lid-logo" transform="translate(300 656)" filter="url(#${u("glow")})">
        <path d="M0 -24 -18 -17v12c0 11.5 7.8 20.2 18 23 10.2-2.8 18-11.5 18-23v-12z"/>
      </g>` : "";
    const HOOD = "M124 490 C 112 378, 132 262, 182 180 C 218 120, 256 76, 288 54 Q 300 46 312 54 C 344 76, 382 120, 418 180 C 468 262, 488 378, 476 490 C 430 516, 368 530, 300 530 C 232 530, 170 516, 124 490 Z";
    const TORSO = "M-10 720 L -10 650 C 14 566, 78 510, 168 484 C 214 470, 254 464, 300 464 C 346 464, 386 470, 432 484 C 522 510, 586 566, 610 650 L 610 720 Z";
    const LINING = "M300 134 C 232 136, 180 196, 172 276 C 164 364, 208 436, 300 458 C 392 436, 436 364, 428 276 C 420 196, 368 136, 300 134 Z";
    const FACE = "M300 152 C 244 154, 198 208, 190 280 C 183 358, 222 422, 300 442 C 378 422, 417 358, 410 280 C 402 208, 356 154, 300 152 Z";
    return `
<svg class="hood" viewBox="0 0 600 720" aria-hidden="true" focusable="false">
  <defs>
    <radialGradient id="${u("void")}" cx="50%" cy="44%" r="58%">
      <stop offset="0" stop-color="#000"/><stop offset=".8" stop-color="#010103"/><stop offset="1" stop-color="#07080c"/>
    </radialGradient>
    <linearGradient id="${u("cloth")}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#23262f"/><stop offset=".45" stop-color="#15171e"/><stop offset="1" stop-color="#08090c"/>
    </linearGradient>
    <linearGradient id="${u("side")}" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#000" stop-opacity=".7"/><stop offset=".28" stop-color="#000" stop-opacity=".05"/>
      <stop offset=".72" stop-color="#000" stop-opacity=".05"/><stop offset="1" stop-color="#000" stop-opacity=".7"/>
    </linearGradient>
    <linearGradient id="${u("top")}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#fff" stop-opacity=".09"/><stop offset=".35" stop-color="#fff" stop-opacity="0"/>
    </linearGradient>
    <linearGradient id="${u("rim")}" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="var(--rim-a, #2f8bff)"/><stop offset="1" stop-color="var(--rim-b, #7fc3ff)"/>
    </linearGradient>
    <linearGradient id="${u("lid")}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#16171e"/><stop offset="1" stop-color="#050506"/>
    </linearGradient>
    <filter id="${u("glow")}" x="-40%" y="-40%" width="180%" height="180%">
      <feGaussianBlur stdDeviation="5" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="${u("soft")}" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="16"/></filter>
    <filter id="${u("tex")}" x="0" y="0" width="100%" height="100%">
      <feTurbulence type="fractalNoise" baseFrequency=".85" numOctaves="2" seed="7" result="n"/>
      <feColorMatrix in="n" type="saturate" values="0" result="g"/>
      <feComposite in="g" in2="SourceAlpha" operator="in"/>
    </filter>
    <clipPath id="${u("clipHood")}"><path d="${HOOD}"/></clipPath>
  </defs>

  <ellipse class="aura" cx="300" cy="280" rx="230" ry="250" filter="url(#${u("soft")})"/>

  <!-- shoulders and chest -->
  <path class="torso" d="${TORSO}" fill="url(#${u("cloth")})"/>
  <path d="${TORSO}" fill="url(#${u("side")})"/>
  <path d="${TORSO}" fill="#fff" opacity=".05" filter="url(#${u("tex")})"/>
  <g fill="none" stroke="#2c2f3b" stroke-width="2" stroke-linecap="round" opacity=".75">
    <path d="M120 540 C 150 560, 170 600, 176 660"/><path d="M480 540 C 450 560, 430 600, 424 660"/>
    <path d="M300 530 L 300 720" stroke="#1d1f28" stroke-width="3"/>
  </g>

  <!-- hood -->
  <path class="hood-shell" d="${HOOD}" fill="url(#${u("cloth")})"/>
  <path d="${HOOD}" fill="url(#${u("side")})"/>
  <path d="${HOOD}" fill="url(#${u("top")})"/>
  <path d="${HOOD}" fill="#fff" opacity=".06" filter="url(#${u("tex")})"/>
  <g clip-path="url(#${u("clipHood")})" fill="none" stroke-linecap="round">
    <path d="M300 50 C 301 78, 301 108, 300 138" stroke="#0b0c10" stroke-width="3"/>
    <path d="M304 52 C 305 80, 305 108, 304 138" stroke="#343745" stroke-width="1.2" opacity=".8"/>
    <path d="M200 196 C 180 250, 170 330, 178 424" stroke="#2b2e3a" stroke-width="2"/>
    <path d="M400 196 C 420 250, 430 330, 422 424" stroke="#2b2e3a" stroke-width="2"/>
    <path d="M246 118 C 226 150, 212 182, 204 214" stroke="#2b2e3a" stroke-width="1.6"/>
    <path d="M354 118 C 374 150, 388 182, 396 214" stroke="#2b2e3a" stroke-width="1.6"/>
  </g>

  <!-- the opening: lining edge, then nothing -->
  <path d="${LINING}" fill="#1b1d25"/>
  <path d="${LINING}" fill="none" stroke="#2d303c" stroke-width="2"/>
  <path class="face" d="${FACE}" fill="url(#${u("void")})"/>
  <g class="eyes" filter="url(#${u("glow")})">
    <path d="M250 300 Q 267 291 284 300 Q 267 306 250 300 Z"/><path d="M316 300 Q 333 291 350 300 Q 333 306 316 300 Z"/>
  </g>

  <!-- drawstrings -->
  <g fill="none" stroke="#5f6272" stroke-width="3" stroke-linecap="round" opacity=".7">
    <path d="M280 446 C 278 480, 276 512, 274 552"/><path d="M320 446 C 322 480, 324 512, 326 552"/>
  </g>
  <rect x="270" y="550" width="8" height="15" rx="3" fill="#8e92a3"/><rect x="322" y="550" width="8" height="15" rx="3" fill="#8e92a3"/>

  <!-- coloured edge light -->
  <g class="rimlight" fill="none" stroke="url(#${u("rim")})" stroke-linecap="round" filter="url(#${u("glow")})">
    <path d="M124 490 C 112 378, 132 262, 182 180 C 218 120, 256 76, 288 54 Q 300 46 312 54" stroke-width="3"/>
    <path d="M312 54 C 344 76, 382 120, 418 180 C 468 262, 488 378, 476 490" stroke-width="3"/>
    <path d="M-10 650 C 14 566, 78 510, 168 484" stroke-width="2.5"/>
    <path d="M610 650 C 586 566, 522 510, 432 484" stroke-width="2.5"/>
    <path d="${LINING}" stroke-width="1" opacity=".35"/>
  </g>
  ${laptop}
</svg>`;
  }
  function mount(el, opts) { el.insertAdjacentHTML("afterbegin", svg(opts)); return el.querySelector("svg.hood"); }
  window.PGHood = { svg, mount };
})();
