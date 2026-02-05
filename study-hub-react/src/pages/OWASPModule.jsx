import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import OWASPLearn from '../components/owasp/OWASPLearn';
import OWASPPractice from '../components/owasp/OWASPPractice';
import { owaspEducationData } from '../data/owasp-data';

const OWASPModule = () => {
    const { id, view } = useParams();
    const navigate = useNavigate();
    const vuln = owaspEducationData[id];

    if (!vuln) {
        return (
            <div className="flex items-center justify-center min-h-[60vh]">
                <div className="text-center space-y-4">
                    <h2 className="text-2xl font-bold text-white uppercase">Module Not Found</h2>
                    <button
                        onClick={() => navigate('/owasp-range')}
                        className="px-6 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-500 transition-all font-bold uppercase tracking-widest text-xs"
                    >
                        Return to Range
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="animate-in fade-in duration-500">
            {view === 'learn' ? (
                <OWASPLearn vuln={vuln} />
            ) : (
                <OWASPPractice vuln={vuln} />
            )}
        </div>
    );
};

export default OWASPModule;
