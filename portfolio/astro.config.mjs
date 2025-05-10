// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';

import react from '@astrojs/react';
import vercel from '@astrojs/vercel';
import partytown from '@astrojs/partytown';
import { storyblok } from '@storyblok/astro';
import { loadEnv } from 'vite';
import basicSsl from '@vitejs/plugin-basic-ssl'

import tailwindcss from '@tailwindcss/vite';

const env = loadEnv("", process.cwd(), 'STORYBLOK');

// https://astro.build/config
export default defineConfig({
  site: 'https://example.com',
  integrations: [mdx(), sitemap(), react(), partytown(), storyblok({
    accessToken: env.STORYBLOK_API_KEY,
    components: {
      blogPost: 'storyblok/BlogPost',
    },
    apiOptions: {
      region: 'eu',
    },
  })],
  vite: {
    plugins: [basicSsl(), tailwindcss()]
  },
  adapter: vercel(),
});