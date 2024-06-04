import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
const mockSignUpResponse = {
  name: 'test',
  email: 'test@gmail.com',
  password: '#FDFAFasdfa',
};
const mockLoginResponse = {
  accessToken: 'testToken',
  refreshToken: 'testRefreshToken',
  userId: '1',
};
const mockRefreshTokenResponse = {
  accessToken: 'testToken',
  refreshToken: 'testRefreshToken',
};
const mockAuthService = {
  signup: jest.fn().mockResolvedValue(mockSignUpResponse),
  login: jest.fn().mockResolvedValue(mockLoginResponse),
  refreshTokens: jest.fn().mockResolvedValue(mockRefreshTokenResponse),
  generateUserToken: jest.fn().mockResolvedValue(mockRefreshTokenResponse),
  storeRefreshToken: jest.fn().mockResolvedValue(null),
};
describe('AuthController', () => {
  let controller: AuthController;
  let service: AuthService;
  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
    expect(service).toBeDefined();
  });
  it('test POST /auth/login', async () => {
    const mockLoginData = { email: 'test@gmail.com', password: '1@s34asda' };
    const result = await controller.login(mockLoginData);
    expect(service.login).toHaveBeenCalledTimes(1);
    expect(service.login).toHaveBeenCalledWith(mockLoginData);
    expect(result).toBe(mockLoginResponse);
  });
  it('test POST /auth/signup', async () => {
    const mockSignupData = {
      email: 'test@gmail.com',
      password: '1@s34asda',
      name: 'test',
    };
    const result = await controller.signUp(mockSignupData);
    expect(service.signup).toHaveBeenCalledTimes(1);
    expect(service.signup).toHaveBeenCalledWith(mockSignupData);
    expect(result).toBe(mockSignUpResponse);
  });
  it('test POST /auth/refresh', async () => {
    const mockRefreshData = { refreshToken: 'test@gmail.com', userId: '123' };
    const result = await controller.refresh(mockRefreshData);
    expect(service.refreshTokens).toHaveBeenCalledTimes(1);
    expect(service.refreshTokens).toHaveBeenCalledWith(mockRefreshData);
    expect(result).toBe(mockRefreshTokenResponse);
  });
});
