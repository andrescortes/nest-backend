import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

@Schema()
export class User {
    // _id: number;
    @Prop({ required: true })
    name: string;
    @Prop({ unique: true, required: true })
    email: string;
    @Prop({ minlength: 6, required: true })
    password?: string;
    @Prop({ default: true })
    isActive: boolean;
    @Prop({ type: [String], default: ['user'] })
    roles: string[];
}

export const UserSchema = SchemaFactory.createForClass(User);