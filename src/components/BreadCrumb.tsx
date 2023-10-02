import { ChevronRightIcon } from "@heroicons/react/24/outline";

type Props = {
    activeTab: number;
    setActiveTab: (tab: number) => void;
    tabItems: string[];
}

const Breadcrumb = (props: Props) => {
    const { activeTab, setActiveTab, tabItems } = props;
    return (
        <nav
            className="flex justify-start items-center"
            aria-label="Breadcrumb"
        >
            <ol className="inline-flex justify-start items-center space-x-1 md:space-x-3">
                {tabItems.map((item, i) => {
                    return (
                        <li key={item} className="flex">
                            <div className="flex justify-evenly items-center gap-3">
                                <button type='submit'
                                    className={`text-neutral-500 underline-offset-4 hover:underline hover:text-neutral-300 ${activeTab === i && " font-semibold text-white"}`}
                                    onClick={() => setActiveTab(i)}
                                >
                                    {item}
                                </button>
                                {i !== tabItems.length-1 && <ChevronRightIcon className='h-3 w-3'/>}
                            </div>
                        </li>
                    );
                })}
            </ol>
        </nav>
    );
}

export default Breadcrumb