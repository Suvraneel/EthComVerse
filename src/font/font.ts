import { Inter } from 'next/font/google'
import localFont from 'next/font/local'

const inter = Inter({ subsets: ['latin'] })
const swera = localFont({
    src: './SweraBoldDemo.otf'
});

export { inter, swera }