import { BadRequestException, InternalServerErrorException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import * as bcrypt from "bcryptjs";

import { CreateUserDto } from './dto/create-user.dto';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginDto } from './dto/login.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { User } from './entities/user.entity';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private readonly jwtService: JwtService,
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        password: bcrypt.hashSync(password, 10),
        ...userData
      });
      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();
      return user;
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${Object.keys(error.keyValue)} already exists`);
      }
      throw new InternalServerErrorException('Something went wrong');
    }
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('Wrong password');
    }

    const { password: _, ...result } = user.toJSON();

    return {
      user: result,
      token: this.getJwtToken({ id: user.id }),
    }
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  async getJwtToken(payload: JwtPayload): Promise<string> {
    const token = this.jwtService.signAsync(payload);
    return token;
  }
}
