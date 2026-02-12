import {
  Injectable,
  NotFoundException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, FilterQuery } from 'mongoose';
import { Tenant, TenantDocument, TenantStatus } from './schemas/tenant.schema';
import { CreateTenantDto } from './dto/create-tenant.dto';
import { UpdateTenantDto } from './dto/update-tenant.dto';
import { RedisLibService } from '@app/redis-lib';

@Injectable()
export class TenantServiceService {
  private readonly logger = new Logger(TenantServiceService.name);

  constructor(
    @InjectModel(Tenant.name)
    private readonly tenantModel: Model<TenantDocument>,
    private readonly cache: RedisLibService,
  ) {}

  private cacheKey(idOrName: string) {
    return `tenant:${idOrName}`;
  }

  async create(dto: CreateTenantDto): Promise<Tenant> {
    try {
      const tenant = new this.tenantModel(dto);
      const saved = await tenant.save();

      await this.cache.set(this.cacheKey(saved._id), saved);
      await this.cache.set(this.cacheKey(saved.name), saved);

      return saved;
    } catch (e: any) {
      if (e?.code === 11000)
        throw new ConflictException('Tenant name already exists');
      throw e;
    }
  }

  async findAll(
    status?: TenantStatus,
    page = 1,
    pageSize = 10,
  ): Promise<{ data: Tenant[]; total: number; meta: any }> {
    const query: FilterQuery<Tenant> = { deleted: false };
    if (status) query.status = status;

    const total = await this.tenantModel.countDocuments(query);

    if (page < 0) {
      const data = await this.tenantModel.find(query).lean().exec();
      return {
        data,
        total,
        meta: { total, page: -1, pageSize: total, totalPages: 1 },
      };
    }

    const skip = (page - 1) * pageSize;
    const data = await this.tenantModel
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(pageSize)
      .lean()
      .exec();

    return {
      data,
      total,
      meta: {
        total,
        page,
        pageSize,
        totalPages: Math.ceil(total / pageSize) || 1,
      },
    };
  }

  async findById(id: string): Promise<Tenant> {
    const key = this.cacheKey(id);
    const cached = await this.cache.get<Tenant>(key);
    if (cached) return cached;

    const doc = await this.tenantModel
      .findOne({ _id: id, deleted: false })
      .lean()
      .exec();
    if (!doc) throw new NotFoundException('Tenant not found');

    await this.cache.set(key, doc, 300);
    return doc;
  }

  async findByName(name: string): Promise<Tenant> {
    const key = this.cacheKey(name);
    const cached = await this.cache.get<Tenant>(key);
    if (cached) {
      this.logger.log('Cache found for ' + key);
      return cached;
    }

    const doc = await this.tenantModel
      .findOne({ name, deleted: false })
      .lean()
      .exec();
    if (!doc) throw new NotFoundException('Tenant not found');

    await this.cache.set(key, doc, 300);
    this.logger.log('Cache set for ' + key);
    return doc;
  }

  async update(id: string, dto: UpdateTenantDto): Promise<Tenant> {
    const updated = await this.tenantModel
      .findOneAndUpdate(
        { _id: id, deleted: false },
        { $set: dto },
        { new: true },
      )
      .lean()
      .exec();
    if (!updated) throw new NotFoundException('Tenant not found');

    await this.cache.set(this.cacheKey(id), updated);
    await this.cache.set(this.cacheKey(updated.name), updated);

    return updated;
  }

  async changeStatus(id: string, status: TenantStatus): Promise<Tenant> {
    const updated = await this.tenantModel
      .findOneAndUpdate(
        { _id: id, deleted: false },
        { $set: { status } },
        { new: true },
      )
      .lean()
      .exec();
    if (!updated) throw new NotFoundException('Tenant not found');

    await this.cache.set(this.cacheKey(id), updated);
    await this.cache.set(this.cacheKey(updated.name), updated);

    return updated;
  }

  async softDelete(id: string): Promise<{ deleted: boolean }> {
    const res = await this.tenantModel
      .findOneAndUpdate(
        { _id: id, deleted: false },
        { $set: { deleted: true, status: TenantStatus.INACTIVE } },
      )
      .lean()
      .exec();
    if (!res) throw new NotFoundException('Tenant not found');

    await this.cache.del(this.cacheKey(id));
    await this.cache.del(this.cacheKey(res.name));

    return { deleted: true };
  }
}
