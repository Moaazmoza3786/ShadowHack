import { useState, useEffect } from 'react';

/**
 * Cyber Range Event Bus
 * Facilitates communication between disparate cyber tools (SOC, C2, Social Eng)
 * to simulate a unified environment.
 */
class CyberRangeBus {
    constructor() {
        this.events = {};
    }

    /**
     * Subscribe to an event
     * @param {string} eventName - Name of the event (e.g., 'C2_BEACON')
     * @param {function} callback - Function to run when event occurs
     */
    on(eventName, callback) {
        if (!this.events[eventName]) {
            this.events[eventName] = [];
        }
        this.events[eventName].push(callback);
        return () => this.off(eventName, callback);
    }

    /**
     * Unsubscribe from an event
     * @param {string} eventName 
     * @param {function} callback 
     */
    off(eventName, callback) {
        if (!this.events[eventName]) return;
        this.events[eventName] = this.events[eventName].filter(cb => cb !== callback);
    }

    /**
     * Emit an event to all subscribers
     * @param {string} eventName 
     * @param {object} data 
     */
    emit(eventName, data) {
        if (!this.events[eventName]) return;

        // Add timestamp if not present
        const payload = {
            timestamp: new Date().toISOString(),
            payload: data
        };

        this.events[eventName].forEach(callback => {
            try {
                callback(payload);
            } catch (error) {
                console.error(`Error in CyberRangeBus listener for ${eventName}:`, error);
            }
        });
    }
}

// Singleton instance
export const cyberRangeBus = new CyberRangeBus();

// Event Constants
export const RANGE_EVENTS = {
    ATTACK_STARTED: 'ATTACK_STARTED',
    LANDING_VISIT: 'LANDING_VISIT',
    CREDENTIAL_CAPTURED: 'CREDENTIAL_CAPTURED',
    C2_BEACON: 'C2_BEACON',
    SIEM_LOG: 'SIEM_LOG',
    DEFENSE_ALERT: 'DEFENSE_ALERT',
    EXPLOIT_SUCCESS: 'EXPLOIT_SUCCESS'
};

// Backward compatibility / Alias
export const CR_TOPICS = RANGE_EVENTS;

// React Hook for consuming events
export const useCyberRangeEvents = (eventName) => {
    const [events, setEvents] = useState([]);

    useEffect(() => {
        if (!eventName) return;

        const handleEvent = (data) => {
            setEvents(prev => [data, ...prev].slice(0, 50)); // Keep last 50 events in buffer
        };

        const unsubscribe = cyberRangeBus.on(eventName, handleEvent);
        return unsubscribe;
    }, [eventName]);

    return events;
};
