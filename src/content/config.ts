import { defineCollection, z } from 'astro:content';

const docs = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    nav: z.string(),
    order: z.number(),
  }),
});

export const collections = { docs };
