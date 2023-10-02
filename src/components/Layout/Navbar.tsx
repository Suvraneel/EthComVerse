'use client'
import { ConnectKitButton } from 'connectkit';
import Link from 'next/link';
import { Suspense } from 'react';
import HamburgerMenu from './HamburgerMenu';

const Navbar = () => {
    const menu = [
        {
            title: 'Home',
            path: '/'
        },
        {
            title: 'Discover',
            path: '/discover'
        },
        {
            title: 'Products',
            path: '/products'
        }
    ]
    return (
        <nav className="flex items-center justify-between p-4 lg:px-6 sticky top-0 bg-black/70 backdrop-blur-sm z-50">
            <div className="block flex-none md:hidden">
                <HamburgerMenu menu={menu} />
            </div>
            <div className="flex w-full items-center">
                <div className="flex w-full md:w-1/3">
                    <Link href="/" className="mr-2 flex w-full items-center justify-center md:w-auto lg:mr-6">
                        {/* <LogoSquare /> */}
                        <div className="ml-2 flex-none text-sm font-medium uppercase md:hidden lg:block">
                            ETHCOMVERSE
                        </div>
                    </Link>
                    {menu.length ? (
                        <ul className="hidden gap-6 text-sm md:flex md:items-center">
                            {menu.map((item) => (
                                <li key={item.title}>
                                    <Link
                                        href={item.path}
                                        className="text-neutral-500 underline-offset-4 hover:text-black hover:underline dark:text-neutral-400 dark:hover:text-neutral-300"
                                    >
                                        {item.title}
                                    </Link>
                                </li>
                            ))}
                        </ul>
                    ) : null}
                </div>
                <div className="hidden justify-center md:flex md:w-1/3">
                    {/* <Search /> */}
                </div>
                <div className="flex justify-end md:w-1/3">
                    <Suspense>
                        <div className='w-fit h-fit rounded-lg border border-cardGray-700 hover:border-gray-700 overflow-hidden'>
                            <ConnectKitButton/>
                        </div>
                    </Suspense>
                </div>
            </div>
        </nav>
    );
}

export default Navbar;