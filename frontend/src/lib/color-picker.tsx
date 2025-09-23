export type HSL = {
    h: number,
    s: number,
    l: number,
}

export function asStyleStr(hsl: HSL): string {
    const {h, s, l} = hsl;
    return `hsl(${h}, ${s}%, ${l}%)`;
}

const usedColors = new Map<number, HSL>();

export function pickPastelColor(targetId: number): HSL {
    let pickedColor = usedColors.get(targetId);
    if (pickedColor !== undefined) {
        return usedColors.get(targetId)!;
    } else {
        pickedColor = {
            h: Math.floor(Math.random() * 360),
            s: Math.floor(60 + Math.random() * 20),
            l: Math.floor(70 + Math.random() * 10),
        };
        usedColors.set(targetId, pickedColor);
    }
    return pickedColor;
}

export function clearUsedColors() {
    usedColors.clear();
}

const mixRatio = 0.5;

export function mixPastelColor(a: HSL, b: HSL): HSL {
    return {
        h: Math.floor(a.h + (b.h - a.h) * mixRatio),
        s: Math.floor(a.s + (b.s - a.s) * mixRatio),
        l: Math.floor(a.l + (b.l - a.l) * mixRatio),
    };
}