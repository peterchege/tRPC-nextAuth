import { PrismaAdapter } from "@auth/prisma-adapter";
import { type GetServerSidePropsContext } from "next";
import {
  getServerSession,
  type DefaultSession,
  type NextAuthOptions,
} from "next-auth";
import { type Adapter } from "next-auth/adapters";
import CredentialsProvider from "next-auth/providers/credentials";
import { verify } from "argon2";

import { loginSchema } from "../validation/index";


import { env } from "~/env";
import { db } from "~/server/db";

/**
 * Module augmentation for `next-auth` types. Allows us to add custom properties to the `session`
 * object and keep type safety.
 *
 * @see https://next-auth.js.org/getting-started/typescript#module-augmentation
 */
declare module "next-auth" {
  interface Session extends DefaultSession {
    user: DefaultSession["user"] & {
      id: string;
      // ...other properties
      // role: UserRole;
    };
  }

  // interface User {
  //   // ...other properties
  //   // role: UserRole;
  // }
}

/**
 * Options for NextAuth.js used to configure adapters, providers, callbacks, etc.
 *
 * @see https://next-auth.js.org/configuration/options
 */
export const authOptions: NextAuthOptions = {

  adapter: PrismaAdapter(db) as Adapter,
  secret:  process.env.NEXTAUTH_SECRET,
  session:{
    strategy: "jwt"
  },

  jwt: {
    secret: "super-secret",
    maxAge: 15 * 24 * 30 * 60, // 15 days
  },
  pages: {
    signIn: "/",
    newUser: "/sign-up",
  },

  providers: [
  CredentialsProvider({
    // The name to display on the sign in form (e.g. "Sign in with...")
    name: "Credentials",
    // `credentials` is used to generate a form on the sign in page.
    // You can specify which fields should be submitted, by adding keys to the `credentials` object.
    // e.g. domain, username, password, 2FA token, etc.
    // You can pass any HTML attribute to the <input> tag through the object.
    credentials: {
      email: { label: "email", type: "email", placeholder: "jsmith@gmail.com" },
      password: { label: "Password", type: "password" }
    },
    async authorize(credentials, req) {
      const creds = await loginSchema.parseAsync(credentials);

      // Add logic here to look up the user from the credentials supplied
      const user = await db.user.findFirst({
        where: { email: creds.email}
      })

      if (!user) {
        // Any object returned will be saved in `user` property of the JWT
        throw new Error('No user found')
      } 

      const isValidPassword = await verify(user.password, creds.password);

      if (!isValidPassword) {
        throw new Error('Incorrect password')
      }

      return {
        id: user.id,
        email: user.email,
        username: user.username,
      };
    }
  })

  ],

  callbacks: {
    jwt: async ({ token, user }) => {


      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.username = user.username
      }

      return token;
    },
    session: async ({ session, token }) => {
      console.log("session session==>",session);
      console.log("session token==>",token);
      if (token) {
        session.id = token.id;
      }
      return session;
    },
  },
};

/**
 * Wrapper for `getServerSession` so that you don't need to import the `authOptions` in every file.
 *
 * @see https://next-auth.js.org/configuration/nextjs
 */
export const getServerAuthSession = (ctx: {
  req: GetServerSidePropsContext["req"];
  res: GetServerSidePropsContext["res"];
}) => {
  return getServerSession(ctx.req, ctx.res, authOptions);
};

