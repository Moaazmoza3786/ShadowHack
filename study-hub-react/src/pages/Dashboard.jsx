import React from 'react';
import { useAppContext } from '../context/AppContext';

import HeroSection from '../components/HeroSection';
import GlobalThreatGlobe from '../components/GlobalThreatGlobe';

const Dashboard = () => {
    const { user } = useAppContext();

    return (
        <div className="space-y-16 pb-20">
            <HeroSection userName={user?.name} />

            <div className="grid grid-cols-1 xl:grid-cols-12 gap-16 items-start">
                <main className="xl:col-span-12 space-y-12">
                    <GlobalThreatGlobe />
                </main>
            </div>
        </div>
    );
};

export default Dashboard;
