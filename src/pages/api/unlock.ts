import type { APIRoute } from 'astro';
import { loadEnv } from 'vite';

export const prerender = false

const env = loadEnv("", process.cwd());

export const POST: APIRoute = async ({ request }) => {
    try {
      const body = await request.json(); // this throws if no body or bad JSON
      const { slug, password } = body;
  
      const passwords = JSON.parse(import.meta.env.POST_PASSWORDS || '{}');
      console.log(passwords);
      const expected = passwords[slug];
  
      if (password && password === expected) {
        
        const hashedPassword = await crypto.subtle.digest(
          'SHA-256',
          new TextEncoder().encode(password)
        );
        const hashArray = Array.from(new Uint8Array(hashedPassword));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: {
            'Set-Cookie': `unlocked_${slug}=${hashHex}; Path=/; HttpOnly; SameSite=Strict`,
          },
        });
      }
  
      return new Response(JSON.stringify({ success: false }), { status: 401 });
    } catch (err) {
      return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400 });
    }
  };
  
