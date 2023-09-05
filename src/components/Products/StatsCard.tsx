import React, { ReactNode } from 'react';
import InfoIcon from '@icons/info';

interface StatProps {
    children?: ReactNode;
    label?: string;
    desc?: string;
    value?: string | number;
}
const StatsCard = (props: StatProps) => {
    const { label, desc, value } = props;
    return (
        <div className='w-full h-full py-4 px-5 rounded-xl flex flex-col items-start justify-start gap-y-2 border grayscale hover:grayscale-0 border-cardGray-700 hover:border-gray-700  min-h-min relative group'>
            <div className='w-full flex flex-row justify-between items-center'>
                <h3 className='text-lg font-semibold'>{label}</h3>
                <div
                    className="w-fit h-fit">
                    <div className='peer'> 
                        <InfoIcon />
                    </div>
                    <div role="tooltip" className="w-[200px] max-w-full h-fit absolute -top-16 -right-0 z-10 px-3 py-2 text-sm font-medium text-white bg-dark rounded-lg shadow-sm bg-cardGray-700 hidden peer-hover:block">
                        {desc}
                        <div className="absolute w-3 h-3 -bottom-1 right-6 bg-cardGray-700 transform rotate-45"></div>
                    </div>
                </div>
            </div>
            <h1 className='text-3xl md:text-4xl font-thin'>{value}</h1>
        </div>
    );
};

export default StatsCard;