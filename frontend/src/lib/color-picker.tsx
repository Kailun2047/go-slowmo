export type HSL = {
    h: number,
    s: number,
    l: number,
}

export function asStyleStr(hsl: HSL): string {
    const {h, s, l} = hsl;
    return `hsl(${h}, ${s}%, ${l}%)`;
}

export function pickPastelColor(): HSL {
    return {
        h: Math.floor(Math.random() * 360),
        s: Math.floor(60 + Math.random() * 20),
        l: Math.floor(70 + Math.random() * 10),
    };
}

const mixRatio = 0.5;

export function mixPastelColor(a: HSL, b: HSL): HSL {
    return {
        h: Math.floor(a.h + (b.h - a.h) * mixRatio),
        s: Math.floor(a.s + (b.s - a.s) * mixRatio),
        l: Math.floor(a.l + (b.l - a.l) * mixRatio),
    };
}