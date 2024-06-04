import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidV4 } from 'uuid';
import { RefreshTokenDto } from './dtos/refresh-token.dto';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { nanoid } from 'nanoid';
import { ResetToken } from './schemas/reset-token.schema';
import { MailService } from 'src/services/mail.service';
import { ResetPasswordDto } from './dtos/reset-password.dto';
@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name)
    private ResetTokenModel: Model<ResetToken>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailService: MailService,
  ) {}
  async signup(signupData: SignupDto) {
    const { email, password, name } = signupData;
    //Check if email is in use
    const emailInUse = await this.UserModel.findOne({
      email: email,
    });
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }
    // Hash password
    const hashPassword = await bcrypt.hash(password, 10);
    // Create user document and save in mongodb
    await this.UserModel.create({
      name,
      email,
      password: hashPassword,
    });
  }
  async login(loginData: LoginDto) {
    const { email, password } = loginData;
    // Find if user exists by email
    const user = await this.UserModel.findOne({ email: email });
    if (!user) {
      throw new UnauthorizedException('Wrong credentials');
    }
    // Compare entered password with existing password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }
    // Generate JWT token
    const tokens = await this.generateUserToken(user._id as string);
    return {
      ...tokens,
      userId: user._id,
    };
  }
  async generateUserToken(userId: string) {
    const accessToken = this.jwtService.sign(
      {
        userId,
      },
      { expiresIn: '1h', secret: this.configService.get<string>('JWT_SECRET') },
    );
    const refreshToken = uuidV4();
    await this.storeRefreshToken(refreshToken, userId);
    return {
      accessToken,
      refreshToken,
    };
  }
  async storeRefreshToken(token: string, userId: string) {
    // Calculate expiry date 3 days from now
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);
    await this.RefreshTokenModel.updateOne(
      {
        userId: userId,
      },
      { $set: { expiryDate, token } },
      { upsert: true },
    );
  }
  async refreshTokens(refreshTokenData: RefreshTokenDto) {
    const { refreshToken, userId } = refreshTokenData;
    // Check token is in refresh token and not expired
    const token = await this.RefreshTokenModel.findOne({
      token: refreshToken,
      // userId: userId,
      expiryDate: { $gte: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('refresh token invalid');
    }
    if (token.userId.toString() !== userId) {
      throw new UnauthorizedException('refresh token invalid');
    }
    // Create new accessToken, refreshToken pair
    return await this.generateUserToken(token.userId as unknown as string);
  }

  async changePassword(userId, changePasswordDto: ChangePasswordDto) {
    const { oldPassword, newPassword } = changePasswordDto;
    // find the user
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    // compare the old password with the password in DB
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }
    // Change user's password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();
  }

  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;
    // check user exists
    const user = await this.UserModel.findOne({ email });
    if (user) {
      const expiryDate = new Date();
      expiryDate.setHours(expiryDate.getHours() + 1);
      // generate reset link for that user
      const resetToken = nanoid(64);
      await this.ResetTokenModel.updateOne(
        {
          userId: user._id,
        },
        {
          $set: { token: resetToken, expiryDate },
        },
        {
          upsert: true,
        },
      );
      // send the link to the user by email
      this.mailService.sendPasswordResetEmail(email, resetToken);
    }
    return {
      message: 'If this user exists, they will receive an email',
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { newPassword, resetToken } = resetPasswordDto;
    // Find a valid reset token document
    const token = await this.ResetTokenModel.findOneAndDelete({
      token: resetToken,
      expiryDate: { $gte: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('Invalid link');
    }
    // Change user password
    const user = await this.UserModel.findById(token.userId);
    if (!user) {
      throw new InternalServerErrorException();
    }
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
  }
}
