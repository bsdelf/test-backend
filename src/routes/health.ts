import { FastifyInstance } from 'fastify';

export const healthRoute = async (fastify: FastifyInstance) => {
  fastify.get(
    '/health',
    {
      schema: {
        response: {
          200: {
            type: 'object',
            properties: {
              status: { type: 'string' },
            },
          },
        },
      },
    },
    async (_request, reply) => {
      reply.send({ status: 'ok' });
    }
  );
};
