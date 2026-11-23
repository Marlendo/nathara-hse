// Run before first paint so later documents in the same tab never flash the
// server-rendered startup overlay. Storage can be unavailable in private or
// restricted browsers; navigation still cannot replay the mounted overlay.
export const BOOT_SPLASH_INIT = `(function(){var e=document.documentElement;try{var k='nathara-hse:boot-splash';var seen=sessionStorage.getItem(k)==='1';e.dataset.natharaSplash=seen?'skip':'show';sessionStorage.setItem(k,'1');}catch(e){document.documentElement.dataset.natharaSplash='show';}})();`
