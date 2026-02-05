import { useState, useEffect } from 'react';

const INITIAL_STATE = {
    money: 500,
    reputation: 0,
    heat: 0,
    inventory: [],
    activeMissions: [],
    mission: { active: false, id: null, step: 0 },
    inbox: [
        { id: 'welcome', sender: 'Admin', subject: 'Welcome to Shadow OS', body: 'Welcome Agent.\n\nSystem initialization complete.\nUse the Terminal to check for active operations.\n\n- The Administrator', read: false, time: 'Now' }
    ]
};

export const useMissionSystem = () => {
    const [state, setState] = useState(() => {
        const saved = localStorage.getItem('shadow_os_state');
        return saved ? JSON.parse(saved) : INITIAL_STATE;
    });

    useEffect(() => {
        localStorage.setItem('shadow_os_state', JSON.stringify(state));
    }, [state]);

    const addMoney = (amount) => setState(prev => ({ ...prev, money: prev.money + amount }));
    const addHeat = (amount) => setState(prev => ({ ...prev, heat: Math.min(100, Math.max(0, prev.heat + amount)) }));
    const addRep = (amount) => setState(prev => ({ ...prev, reputation: prev.reputation + amount }));

    const startMission = (missionId, briefing) => {
        setState(prev => ({
            ...prev,
            mission: { active: true, id: missionId, step: 1 },
            inbox: [
                {
                    id: Date.now().toString(),
                    sender: 'Handler',
                    subject: `OP: ${missionId.toUpperCase()} - Briefing`,
                    body: briefing,
                    read: false,
                    time: 'Now'
                },
                ...prev.inbox
            ]
        }));
    };

    const updateMissionStep = (step) => {
        setState(prev => ({
            ...prev,
            mission: { ...prev.mission, step }
        }));
    };

    const buyItem = (item) => {
        if (state.money >= item.price && !state.inventory.includes(item.id)) {
            setState(prev => ({
                ...prev,
                money: prev.money - item.price,
                inventory: [...prev.inventory, item.id]
            }));
            return true;
        }
        return false;
    };

    return {
        state,
        addMoney,
        addHeat,
        addRep,
        startMission,
        updateMissionStep,
        buyItem
    };
};
