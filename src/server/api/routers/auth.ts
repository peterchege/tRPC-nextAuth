import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { hash } from "argon2";

import {
  createTRPCRouter,
  protectedProcedure,
  publicProcedure,
} from "~/server/api/trpc";

const loginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(4).max(12),
  });
  
const signUpSchema = loginSchema.extend({
    username: z.string(),
  });

export const loginRouter = createTRPCRouter({
    signup: publicProcedure
    .input(signUpSchema)
    .mutation( async ({ input, ctx }) => {
        const { username, email, password } = signUpSchema.parse(input);

        const exists = await ctx.db.user.findFirst({
            where: { email },
          });
      
          if (exists) {
            throw new TRPCError({
              code: "CONFLICT",
              message: "User already exists.",
            });
          }

        const hashedPassword = await hash(password);

        const result = await ctx.db.user.create({
        data: { username, email, password: hashedPassword },
        });

        return {
        status: 201,
        message: "Account created successfully",
        result: result.email,
        };

    }),

});
