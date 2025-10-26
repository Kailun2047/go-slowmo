import { groupBy } from 'lodash';
import { useBoundStore } from "./store";
import { asStyleStr, pickPastelColor } from '../lib/color-picker';

const parkedColor = '#f68647';

export function GlobalStructList() {
    const parked = useBoundStore((state) => state.parked);
    const isRunning = useBoundStore((state) => state.isRunning);
    
    const byWaitReason = groupBy(parked, (parkedG) => parkedG.waitReason);
    const parkedGroups = [];
    for (const reason in byWaitReason) {
        const goroutines = byWaitReason[reason].map(g => (
            <div className='go-g' key={'g'+g.id} style={{backgroundColor: asStyleStr(pickPastelColor(g.id))}}>
                {'g' + g.id}<br />
                {g.entryFunc}
            </div>
        ));
        parkedGroups.push((
            <div className='park-group' key={reason}>
                <div className='park-wait-reason'>{reason}</div>
                <div className='go-struct'>
                    {goroutines}
                </div>
            </div>
        ));
    }
    return isRunning? (
        <div className='global-struct-list'>
            <div className='go-struct-wrapper' key='parked' style={{borderColor: parkedColor}}>
                <div className='go-struct-name' style={{width: '100px', color: parkedColor}}>"gopark"ing lot</div>
                {parkedGroups}
            </div>
        </div>
    ): undefined;
}