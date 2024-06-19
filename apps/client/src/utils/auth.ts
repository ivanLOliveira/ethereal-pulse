import jwt from 'jsonwebtoken';
import bcry from "bcryptjs"

const SECRET_KEY = 'your-secret-key';

// Simulate a user database
const users = new Map<string, string>();

export interface JwtPayload {
  username: string;
}

export function registerUser( email: string,password: string): void {
  const hashedPassword = bcry.hashSync(password, 10);
  users.set(email, hashedPassword);
}

export function authenticateUser(username: string, password: string): string | null {
  const hashedPassword = users.get(username);
  if (hashedPassword && bcry.compareSync(password, hashedPassword)) {
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1m' });

    return token;
  }
  return null;
}

export function verifyToken(token: string): boolean{
  try {
    const decoded = jwt.verify(token, SECRET_KEY) as JwtPayload;
    if (decoded){
      return true
    } 
    return false;
  } catch (error) {
    return false;
  }
}
export function expireConnvertMinutes(minutes:number):Date{
  const time=new Date(Date.now() + minutes * 60 * 1000);
  return time;
}

export function isRegisteredEmail(email: string): boolean {
  return users.has(email);
}
